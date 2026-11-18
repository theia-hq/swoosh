//! The server side of an Open: one admitted stream to a peer, spliced onto the control connection that
//! asked for it.
//!
//! Every check that can refuse without reaching out runs first: the peer is not this machine, the slip
//! is not one anyone may hold, the run has a reach slot for the lane, and the peer's lane has room. Only
//! then is the control slot released, the standing renewed when due, and the peer dialed. Once attached,
//! the two streams are spliced in SWC1 frames, one direction at a time, until both are settled or the
//! local client is gone; a finished upload is answered with Landed once the peer holds it.

use core::pin::pin;
use core::time::Duration;
use std::os::fd::{BorrowedFd, OwnedFd, RawFd};
use std::time::SystemTime;

use bifrost::{Discovery, NodeId, RefusalDetail, Session as _, Transport, WriteEnd};
use nauthy::Service;
use tokio::io::unix::AsyncFd;
use tokio::io::{
    self, AsyncBufRead, AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, Interest,
};
use tokio::sync::{Semaphore, SemaphorePermit};
use tokio::time::Instant;

use super::PROVEN_ROUTES;
use super::socket::splice::{FramedWriter, UploadCut, upload};
use super::socket::{OpenLane, OpenRefusal, OpenRequest, Response};
use crate::credential::{Credential, admits_anyone_at};
use crate::home::Home;
use crate::peers::{
    DIAL_TIMEOUT, DialFailure, Lane, MAIN_OPEN_TIMEOUT, OPEN_TIMEOUT, OpenError, Peers, Presents,
};
use crate::reaching::ResolveError;
use crate::renewal::{Fetch, OPEN_RENEWAL, OpenRenewal};

/// The most streams the run's Opens hold at once, across every peer and lane.
pub const MAX_REACH: usize = 256;

/// The most of [`MAX_REACH`] that Bulk, slip and Isolated streams may hold together, so the rest is
/// always there for an ordinary Main stream.
pub const MAX_BEYOND_MAIN: usize = 224;

const _: () = assert!(MAX_BEYOND_MAIN < MAX_REACH);

/// How long a splice whose local client has closed its socket in both directions may go on sending what
/// the client wrote, on every lane, and how long after the client's End the peer has to hold the whole
/// upload before Landed. Each is counted from its moment and never extended by progress, so a peer taking
/// a byte at a time cannot hold the splice; at the deadline the splice is dropped, and with it the reach
/// slots, the lane count and the session, or the isolated connection.
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

/// The longest an Open runs before its reply is written: a renewal, then a held lane's open that fails at
/// its deadline, the one redial that follows and its open again, then the reply's write. An isolated
/// connection's dial and its open fit within the same. A client waiting on the reply waits longer than
/// this, so its own bound only ends a wait on a resident that has stopped answering.
pub(crate) const OPEN_REPLY_BOUND: Duration = OPEN_RENEWAL
    .saturating_add(OPEN_TIMEOUT)
    .saturating_add(DIAL_TIMEOUT)
    .saturating_add(OPEN_TIMEOUT)
    .saturating_add(REPLY_TIMEOUT);

// A Main open's deadline is the shorter, so the bound counts Bulk's.
const _: () = assert!(MAIN_OPEN_TIMEOUT.as_millis() <= OPEN_TIMEOUT.as_millis());

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
                let (connection, to_peer, from_peer) = match opened {
                    Ok(opened) => opened,
                    Err(refusal) => return refuse(&mut to_client, refusal).await,
                };
                let info = connection.conn_info();
                // Closing a connection discards what the peer has not acknowledged. The splice has
                // already waited, within its deadline, for the peer to hold a finished upload, so the
                // close follows at once: after a delivery, nothing is lost; without one, the close is
                // the reset a held lane cannot send.
                attach(from_client, to_client, from_peer, to_peer, info, &gone).await;
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
            Ok((info, to_peer, from_peer)) => {
                attach(from_client, to_client, from_peer, to_peer, info, &gone).await;
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

/// Reply Attached with the path the stream rides, then splice.
///
/// However this ends, short of a successful shutdown of `to_peer`, the peer's stream is aborted: a failed
/// reply, an upload cut off or malformed, a failed write toward the peer, a failed stream from the peer, a
/// drain cut at its deadline, and this future dropped by `Stop` or a panic. A client gone while it splices does not drop this
/// future: what it wrote drains, a drain that reaches the client's End in time ends cleanly, and only one
/// still running at the deadline is aborted.
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
    PW: AsyncWrite + WriteEnd + Unpin,
{
    // Armed before anything can return, so no early exit leaves the peer a clean end.
    let to_peer = ToPeer::arm(to_peer);
    let reply = Response::Attached(info);
    if !matches!(
        tokio::time::timeout(REPLY_TIMEOUT, reply.write(&mut to_client)).await,
        Ok(Ok(()))
    ) {
        return;
    }
    splice(
        from_client,
        to_client,
        from_peer,
        to_peer,
        gone.wait(),
        gone.finished_writing(),
    )
    .await;
}

/// Move a stream both ways in SWC1 frames, each direction on its own, until both are settled.
///
/// Toward the peer, the client's Data bodies go to the peer's stream, and only the client's End shuts
/// it down cleanly. An end of the client's writing without End (an end of file, a half-close, a failed
/// read) is a cut-off: the peer's stream is aborted at once and the download keeps flowing. A malformed
/// frame or a failed write toward the peer aborts it and ends the splice.
///
/// Toward the client, the peer's bytes go out as Data frames, and the peer's clean end as End. A peer
/// whose stream fails while the upload runs ends the splice at once: the upload toward the peer is
/// aborted, and the client's connection is closed with no End, which is how the client learns it was cut
/// off, even one that is idle and writing nothing. The resident shuts its writing only as the splice's
/// last act, so the client's hang-up stays readable throughout and Landed can still follow the
/// download's End.
///
/// Once the client's End is read and the peer's stream shut down, the peer must hold every byte and the
/// end within [`HANGUP_DRAIN`] of that End, never extended. Then Landed is written. A transport that says
/// the peer will never hold it gets no Landed, and the download still runs to its end; a deadline passed
/// ends the splice with no Landed, which is the client's cut-off. Only an isolated connection can
/// still reset the peer then, by its close; a held lane's stream has already ended cleanly.
///
/// `hangup` resolves when the client has closed its socket in both directions. Then the direction toward
/// the client stops at once, and what the client wrote before it went goes on toward the peer for at most
/// [`HANGUP_DRAIN`] from that moment; once its End arrives, the splice waits for the peer to hold the
/// upload, never past the same deadline, so an isolated close loses nothing, and ends.
///
/// `finished` resolves when the client has finished writing, gone or half-closed. It is watched only
/// once the download has ended and while the upload still runs: then what the client wrote goes on
/// toward the peer for at most [`HANGUP_DRAIN`], so a client that stopped writing without End cannot hold
/// a splice whose peer takes nothing. An End read within that bound still earns Landed, since a
/// half-closed client still reads. A client still writing to a peer that has ended stays live.
///
/// A write toward the client that fails ends only that direction: the client's frames still go to the
/// peer.
///
/// Each direction holds one buffer of a frame header plus 8 KiB and no more: toward the peer, the client
/// reader's own buffer, read in place; toward the client, the framing writer's.
pub(crate) async fn splice<R, W, PR, PW>(
    from_client: R,
    to_client: W,
    from_peer: PR,
    to_peer: ToPeer<PW>,
    hangup: impl Future<Output = ()>,
    finished: impl Future<Output = ()>,
) where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
    PR: AsyncRead + Unpin,
    PW: AsyncWrite + WriteEnd + Unpin,
{
    let (landed, verdict) = tokio::sync::oneshot::channel();
    let (over, downloaded) = tokio::sync::oneshot::channel();
    let mut down = pin!(download(
        from_peer,
        FramedWriter::new(to_client),
        verdict,
        over
    ));
    // The writer for the close, or none once a write toward the client failed. The block owns the upload,
    // so leaving it drops the guard toward the peer before the close; and the close is the splice's last
    // act, since the resident's own shutdown reads on the hang-up watch as a client gone.
    let closing = 'spliced: {
        let mut up = pin!(upload_to(from_client, to_peer));
        let mut hangup = pin!(hangup);
        // Polled from the start, it waits first for the download to be over, so an upload's data never
        // wakes the watch before then.
        let mut finished = pin!(async {
            let _ = downloaded.await;
            finished.await;
        });
        // Set once the download has settled.
        let mut settled: Option<Downloaded<W>> = None;

        let uploaded = loop {
            tokio::select! {
                uploaded = &mut up => break uploaded,
                done = &mut down, if settled.is_none() => match done {
                    // Nothing more can reach the client, and an idle client would read nothing until
                    // it wrote: the upload is aborted and the client's connection closed, now.
                    Downloaded::PeerCut(writer) => break 'spliced Some(writer),
                    done => settled = Some(done),
                },
                () = &mut hangup => {
                    drain(up).await;
                    break 'spliced None;
                }
                () = &mut finished => {
                    match tokio::time::timeout_at(Instant::now() + HANGUP_DRAIN, &mut up).await {
                        Ok(uploaded) => break uploaded,
                        Err(_) => {
                            tracing::debug!("a finished client's upload was cut at the drain deadline");
                            break 'spliced None;
                        }
                    }
                }
            }
        };
        match uploaded {
            // The client's writing ended without End: the peer was aborted as it ended, and the
            // download goes on. No Landed can follow.
            Err(UploadCut::Cut(error)) => {
                tracing::debug!(%error, "a client's upload was cut off");
                drop(landed);
            }
            Err(cut) => {
                tracing::debug!(%cut, "a splice ended toward the peer");
                break 'spliced None;
            }
            Ok((ended, half)) => {
                let mut delivery = pin!(tokio::time::timeout_at(
                    ended + HANGUP_DRAIN,
                    half.delivered()
                ));
                loop {
                    tokio::select! {
                        delivered = &mut delivery => match delivered {
                            Ok(Ok(())) => {
                                let _ = landed.send(());
                                break;
                            }
                            // The peer will never hold it: Landed is withheld, and the download
                            // still runs to its end, so a peer that stopped reading early still
                            // hands the client its reply.
                            Ok(Err(error)) => {
                                tracing::debug!(%error, "an upload did not land");
                                drop(landed);
                                break;
                            }
                            Err(_) => {
                                tracing::debug!("an upload did not land by its deadline");
                                break 'spliced None;
                            }
                        },
                        done = &mut down, if settled.is_none() => settled = Some(done),
                        () = &mut hangup => {
                            // Nobody is left to tell; an isolated close still waits for the delivery,
                            // never past the drain from now nor the deadline from the End.
                            let by = Instant::now() + HANGUP_DRAIN;
                            let _ = tokio::time::timeout_at(by, delivery).await;
                            break 'spliced None;
                        }
                    }
                }
            }
        }
        let settled = match settled {
            Some(settled) => settled,
            None => tokio::select! {
                done = &mut down => done,
                () = &mut hangup => break 'spliced None,
            },
        };
        match settled {
            Downloaded::Settled(writer) | Downloaded::PeerCut(writer) => Some(writer),
            Downloaded::Lost => None,
        }
    };
    if let Some(mut writer) = closing {
        let _ = tokio::time::timeout(REPLY_TIMEOUT, writer.shutdown()).await;
    }
}

/// The client gone, finish the upload within [`HANGUP_DRAIN`] from now: a cut-off or a drain past the
/// deadline drops the guard, which aborts the peer, and a finished upload waits, within the same bound,
/// for the peer to hold it.
async fn drain<F, PW>(up: core::pin::Pin<&mut F>)
where
    F: Future<Output = Result<(Instant, PW), UploadCut>>,
    PW: WriteEnd,
{
    let drained_by = Instant::now() + HANGUP_DRAIN;
    match tokio::time::timeout_at(drained_by, up).await {
        Ok(Ok((_, half))) => {
            let _ = tokio::time::timeout_at(drained_by, half.delivered()).await;
        }
        Ok(Err(cut)) => tracing::debug!(%cut, "a gone client's upload ended short"),
        Err(_) => tracing::debug!("a gone client's upload was cut at the drain deadline"),
    }
}

/// Carry the client's frames to the peer until its End, then shut the peer's stream down. Returns when
/// the End was read and the peer's bare half, no longer armed; on any cut the guard drops here, which
/// aborts the peer's stream at once.
async fn upload_to<R, PW>(
    mut from_client: R,
    mut to_peer: ToPeer<PW>,
) -> Result<(Instant, PW), UploadCut>
where
    R: AsyncBufRead + Unpin,
    PW: AsyncWrite + WriteEnd + Unpin,
{
    upload(&mut from_client, to_peer.half().map_err(UploadCut::Peer)?).await?;
    let ended = Instant::now();
    let half = to_peer.finish().await.map_err(UploadCut::Peer)?;
    Ok((ended, half))
}

/// How the download toward the client ended, which decides how the splice closes.
enum Downloaded<W> {
    /// Both the download and the upload's verdict are settled: the writer, for the final close.
    Settled(FramedWriter<W>),
    /// The peer's stream failed: the writer, to close toward the client at once, with no End.
    PeerCut(FramedWriter<W>),
    /// A write toward the client failed, or the last frame was not taken within [`REPLY_TIMEOUT`].
    Lost,
}

/// Frame the peer's bytes toward the client: Data while the peer sends, End at its clean end, nothing
/// at a failed one. After End the writing stays open for the upload's verdict, and Landed goes out when
/// `verdict` says so; a dropped `verdict` sender means none will. `over` is told once the download has
/// ended cleanly; a failed peer stream or a write failure toward the client drops it, which says the
/// same. Every read is cancel-safe and every frame write runs to its end inside this one future, so a
/// frame is never cut by a select.
async fn download<PR, W>(
    mut from_peer: PR,
    mut to_client: FramedWriter<W>,
    mut verdict: tokio::sync::oneshot::Receiver<()>,
    over: tokio::sync::oneshot::Sender<()>,
) -> Downloaded<W>
where
    PR: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    /// What woke the download.
    enum Next {
        /// The upload's verdict: landed, or not.
        Verdict(bool),
        /// A read from the peer.
        Read(io::Result<usize>),
    }
    let (mut downloading, mut waiting) = (true, true);
    let mut over = Some(over);
    loop {
        if !downloading && let Some(over) = over.take() {
            let _ = over.send(());
        }
        let next = tokio::select! {
            // The verdict first, so a peer that never pauses cannot hold Landed back.
            biased;
            said = &mut verdict, if waiting => Next::Verdict(said.is_ok()),
            read = from_peer.read(to_client.body()), if downloading => Next::Read(read),
            else => return Downloaded::Settled(to_client),
        };
        match next {
            Next::Verdict(landed) => {
                waiting = false;
                let written = match (landed, downloading) {
                    (false, _) => true,
                    (true, true) => to_client.write_landed().await.is_ok(),
                    (true, false) => last(to_client.write_landed()).await,
                };
                if !written {
                    return Downloaded::Lost;
                }
            }
            Next::Read(Ok(0)) => {
                downloading = false;
                let written = if waiting {
                    to_client.write_end().await.is_ok()
                } else {
                    last(to_client.write_end()).await
                };
                if !written {
                    return Downloaded::Lost;
                }
            }
            Next::Read(Ok(read)) => {
                if let Err(error) = to_client.write_data(read).await {
                    tracing::debug!(%error, "a splice stopped writing to its client");
                    return Downloaded::Lost;
                }
            }
            Next::Read(Err(error)) => {
                tracing::debug!(%error, "a peer's stream failed mid-splice");
                return Downloaded::PeerCut(to_client);
            }
        }
    }
}

/// Whether the last frame toward the client, the one after which both directions are settled, was
/// written within [`REPLY_TIMEOUT`], so a client that stops reading cannot hold the splice past them.
/// An earlier End or Landed waits as a Data frame does, so a reader that pauses while its upload runs
/// never loses a download that came whole.
async fn last(write: impl Future<Output = io::Result<()>>) -> bool {
    matches!(tokio::time::timeout(REPLY_TIMEOUT, write).await, Ok(Ok(())))
}

/// The send half toward the peer for the life of an attached Open. Dropped before a successful
/// [`finish`](Self::finish), it aborts the stream, so the peer reads `ConnectionReset` where a
/// transport's write half dropped as it is would end the stream cleanly: at the drain deadline, after a
/// cut-off or malformed upload, after a failed reply or write toward the peer, after the peer's own stream
/// failed, and when `Stop` or a panic drops the Open. Only the client's End leads to `finish`, so a stream the client did not end is never
/// shut down cleanly.
pub(crate) struct ToPeer<W: WriteEnd>(Option<W>);

impl<W: WriteEnd> ToPeer<W> {
    fn arm(half: W) -> Self {
        Self(Some(half))
    }

    /// The half, to write the upload through, while armed. Only [`finish`](Self::finish) takes it out,
    /// and it consumes the guard, so this never fails in practice.
    fn half(&mut self) -> io::Result<&mut W> {
        self.0
            .as_mut()
            .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))
    }
}

impl<W: AsyncWrite + WriteEnd + Unpin> ToPeer<W> {
    /// Shut the stream down cleanly and hand back the bare half, disarmed, to wait on its delivery. A
    /// shutdown that fails, or this future dropped before it completes, aborts the stream.
    async fn finish(mut self) -> io::Result<W> {
        self.half()?.shutdown().await?;
        self.0
            .take()
            .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))
    }
}

impl<W: WriteEnd> Drop for ToPeer<W> {
    fn drop(&mut self) {
        if let Some(half) = &mut self.0 {
            half.abort();
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
const UNREADABLE_HOME: &str = "this machine's home or badge could not be read";

/// Watches a control connection for its client closing the socket in both directions.
///
/// A half-close is not that: a client that has finished writing still reads the peer's reply. Only a
/// socket closed both ways, which a client that exits or drops it leaves, reads as closed for writing
/// on this side: the kqueue write filter's end of file on macOS, a hang-up on Linux. The resident shuts
/// its own writing only as a splice's last act, after its last look at this watch, so this reading is
/// never its own. The same watch also tells
/// when the client has finished writing, gone or half-closed: the read side's end of file, seen even
/// with the client's bytes still unread. The watch has a registration of its own, on a duplicate of the
/// connection's descriptor, so clearing its readiness never takes a wakeup from the splice reading or
/// writing the same socket. The duplicate is a second descriptor per Open.
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
