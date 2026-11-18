//! The server side of an Open: one admitted stream to a peer, spliced onto the control connection that
//! asked for it.
//!
//! Every check that can refuse without reaching out runs first: the peer is not this machine, the slip
//! is not one anyone may hold, and the run has a reach slot for the lane. Only then is the control slot
//! released, the standing renewed when due, and the peer dialed. Once attached, the two streams are
//! spliced one direction at a time until both are done, or until the local client is gone entirely.

use core::pin::pin;
use core::time::Duration;
use std::os::fd::{BorrowedFd, OwnedFd, RawFd};
use std::time::SystemTime;

use bifrost::{Discovery, NodeId, RefusalDetail, Session as _, Transport};
use nauthy::Service;
use tokio::io::unix::AsyncFd;
use tokio::io::{self, AsyncBufRead, AsyncRead, AsyncWrite, AsyncWriteExt as _, Interest};
use tokio::sync::{Semaphore, SemaphorePermit};

use super::PROVEN_ROUTES;
use super::socket::{OpenLane, OpenRefusal, OpenRequest, Response};
use crate::credential::{Credential, admits_anyone_at};
use crate::home::Home;
use crate::peers::{DialFailure, Lane, OPEN_TIMEOUT, OpenError, Peers, Presents};
use crate::renewal::{Fetch, OpenRenewal};

/// The most streams the run's Opens hold at once, across every peer and lane.
pub const MAX_REACH: usize = 256;

/// The most of [`MAX_REACH`] that Bulk, slip and Isolated streams may hold together, so the rest is
/// always there for an ordinary Main stream.
pub const MAX_BEYOND_MAIN: usize = 224;

const _: () = assert!(MAX_BEYOND_MAIN < MAX_REACH);

/// How long a splice whose local client has closed its socket in both directions may go on sending what
/// the client wrote before it went, on every lane. Counted from the hang-up and never extended by
/// progress, so a peer taking a byte at a time cannot hold the splice; at the deadline the splice is
/// dropped, and with it the reach slots, the lane count and the session, or the isolated connection.
pub const HANGUP_DRAIN: Duration = Duration::from_secs(4);

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
    /// home's standing as it reads now. A standing that cannot be presented ends the Open here.
    // `core::io::sink` is still unstable, so the sink for the warning comes from `std`.
    #[allow(clippy::std_instead_of_core)]
    async fn presents(
        &self,
        service: &Service,
        slip: Option<nauthy::Link>,
    ) -> Result<Presents, OpenRefusal> {
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
            OpenRefusal::StandingEnded
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
}

impl<T: Transport, D: Discovery, F: Fetch> Opens for Opener<'_, '_, '_, T, D, F> {
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
        // A stream may live for hours; the control slot is for answering the socket, not for that.
        drop(control);
        // From here the Open reaches out, so a client gone in the meantime ends it at once: nobody is
        // left to read the reply.
        let lane = open.lane();
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
            Err(refusal) => return refuse(&mut to_client, refusal).await,
        };
        let held_lane = match lane {
            OpenLane::Main => Lane::Main,
            OpenLane::Bulk => Lane::Bulk,
            OpenLane::Isolated => {
                let opened = until_gone(&gone, async {
                    let connection = self
                        .peers
                        .isolated(peer, hints)
                        .await
                        .map_err(|error| failed(&error))?;
                    let connector = presents.connector(peer, service);
                    match tokio::time::timeout(OPEN_TIMEOUT, connector.open_on(&connection)).await {
                        Ok(Ok((writer, reader))) => Ok((connection, writer, reader)),
                        Ok(Err(error)) => Err(failed(&OpenError::Open(error))),
                        Err(_) => Err(OpenRefusal::Timeout),
                    }
                })
                .await;
                let Some(opened) = opened else { return };
                let (connection, to_peer, from_peer) = match opened {
                    Ok(opened) => opened,
                    Err(refusal) => return refuse(&mut to_client, refusal).await,
                };
                let info = connection.conn_info();
                attach(from_client, to_client, from_peer, to_peer, info, &gone).await;
                // Dropping the connection closes it; what the peer has not taken by now is lost.
                drop((connection, held));
                return;
            }
        };
        let opened = until_gone(
            &gone,
            self.peers
                .open_attached(peer, hints, service, held_lane, presents),
        )
        .await;
        let Some(opened) = opened else { return };
        match opened {
            Ok((info, to_peer, from_peer)) => {
                attach(from_client, to_client, from_peer, to_peer, info, &gone).await;
            }
            Err(error) => refuse(&mut to_client, failed(&error)).await,
        }
        drop(held);
    }
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
    let reply = Response::OpenRefusal(refusal);
    let _ = tokio::time::timeout(REPLY_TIMEOUT, reply.write(to_client)).await;
    let _ = to_client.shutdown().await;
}

/// Reply Attached with the path the stream rides, then splice.
async fn attach<R, W, PR, PW>(
    from_client: R,
    mut to_client: W,
    from_peer: PR,
    to_peer: PW,
    info: bifrost::ConnInfo,
    gone: &ClientGone,
) where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
    PR: AsyncRead + Unpin,
    PW: AsyncWrite + Unpin,
{
    let reply = Response::Attached(info);
    if !matches!(
        tokio::time::timeout(REPLY_TIMEOUT, reply.write(&mut to_client)).await,
        Ok(Ok(()))
    ) {
        return;
    }
    splice(from_client, to_client, from_peer, to_peer, gone.wait()).await;
}

/// Move bytes both ways, each direction on its own. The client's end of writing shuts the peer's
/// writing and the peer's end shuts the client's, while the reverse keeps flowing; the splice is done
/// when both directions are, or when either fails.
///
/// `hangup` resolves when the client has closed its socket in both directions. Then the direction
/// toward the client stops at once, and what the client wrote before it went goes on toward the peer
/// for at most [`HANGUP_DRAIN`] from that moment; the splice then ends, dropping everything it holds.
/// The hang-up is watched only while this side still writes to the client: once it has shut that
/// writing, a hang-up can be its own (macOS reports one), and the client's direction sees a departed
/// client as its own end of file or error.
///
/// Each direction holds one 8 KiB buffer and no more: toward the peer, the client reader's own buffer,
/// read in place; toward the client, the one buffer of the copy.
pub(crate) async fn splice<R, W, PR, PW>(
    mut from_client: R,
    mut to_client: W,
    mut from_peer: PR,
    mut to_peer: PW,
    hangup: impl Future<Output = ()>,
) where
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
    let mut hangup = pin!(hangup);
    let (mut up_done, mut down_done) = (false, false);
    loop {
        tokio::select! {
            ended = &mut up, if !up_done => {
                if let Err(error) = ended {
                    tracing::debug!(%error, "a splice ended toward the peer");
                    return;
                }
                up_done = true;
            }
            ended = &mut down, if !down_done => {
                if let Err(error) = ended {
                    tracing::debug!(%error, "a splice ended toward the client");
                    return;
                }
                down_done = true;
            }
            () = &mut hangup, if !down_done => break,
        }
        if up_done && down_done {
            return;
        }
    }
    if !up_done {
        // One deadline from the hang-up; nothing the peer takes moves it.
        let _ = tokio::time::timeout(HANGUP_DRAIN, &mut up).await;
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

/// Watches a control connection for its client closing the socket in both directions.
///
/// A half-close is not that: a client that has finished writing still reads the peer's reply. Only a
/// socket closed both ways, which a client that exits or drops it leaves, reads as closed for writing
/// on this side: the kqueue write filter's end of file on macOS, a hang-up on Linux. The watch has a
/// registration of its own, on a duplicate of the connection's descriptor, so clearing its readiness
/// never takes a wakeup from the splice writing to the same socket.
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
        let watch = unsafe { AsyncFd::register_with_interest(duplicate, Interest::WRITABLE) }?;
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
}

#[cfg(test)]
#[path = "opening_tests.rs"]
mod tests;
