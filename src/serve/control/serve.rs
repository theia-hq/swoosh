use core::time::Duration;
use std::sync::Arc;

use nauthy::{Denylist, VerifyKey};
use tightbeam::identity::AsNodeId as _;
use tightbeam::open_policy::Never;
use tightbeam::tunnel::{
    BoxRead, BoxWrite, CancellationToken, Handler, ServeError, Served, ServiceCatalog,
};
use tokio::io::{self, AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::sync::watch;

use crate::contacts::Contacts;
use crate::peer::OwnDevice;
use crate::serve::{StopKind, StopSource};

/// The `control.serve` handler: one request per stream, [`Request::List`] or [`Request::Stop`], answered
/// with one [`Answer`] byte.
///
/// MEMBER-only (`type Exposure = Never`, bound with `member_service` by [`bind_serve`](super::bind_serve)):
/// the gate admits a family badge, and tightbeam's floor refuses anything that is not a whole-node member
/// before any `Response::Ok`, so a stranger and a delegate's slip get the uniform refusal and this handler
/// never runs.
///
/// It reads exactly one byte, under [`REQUEST_DEADLINE`], and never a second: a stream carries one request,
/// and whatever follows it is never parsed. Every answer is bounded too, so a member that grants no credit
/// cannot park the handler on it: a list, `NotYet` or `BadRequest` writes and shuts down under one
/// [`REQUEST_DEADLINE`], and a stop's `Done` and its `shutdown` take one each, then at most
/// [`ACK_GRACE`] for the caller's close. A stream this handler does not
/// answer (silence, an end with no byte, a refused stop, an answer past the bound) is dropped unshut, which
/// tightbeam turns into a reset: the caller can never read a clean end as an answer.
///
/// Public so the integration proofs drive the SAME handler `serve` binds, through
/// [`bind_serve`](super::bind_serve).
pub struct Serve {
    /// The served catalog, cut once when `serve` assembled its routes; [`Request::List`] writes it.
    catalog: ServiceCatalog,
    /// A clone of the node's teardown token: the capability to request a stop, never the teardown itself.
    cancel: CancellationToken,
    /// Where the node notes how it was asked to stop, read at teardown to say who.
    source: Arc<StopSource>,
    /// Whether the run's first sync round has ended; a [`Request::Stop`] waits for it.
    hold: Hold,
    /// The revocations the gate reads, the same instance. A device revoked after its stream was admitted
    /// is refused here, at the request, since the gate asked only at admission. Only the peer's key is asked
    /// again, since the handler sees no more of the admission than the key: a revocation by badge id, a
    /// revoked root and a pin change are left to the live cut, which ends the whole session.
    revoked: Arc<Denylist>,
}

impl Serve {
    /// The handler over `catalog`, stopping the node through `cancel` and noting the caller in `source`,
    /// with stops held by `hold` and refused to a key `revoked` holds. Crate-only: `serve` builds it through
    /// [`bind_serve`](super::bind_serve), which hands it the gate's own revocations.
    pub(crate) fn new(
        catalog: ServiceCatalog,
        cancel: CancellationToken,
        source: Arc<StopSource>,
        hold: Hold,
        revoked: Arc<Denylist>,
    ) -> Self {
        Self {
            catalog,
            cancel,
            source,
            hold,
            revoked,
        }
    }

    /// Answer the one request on a stream from `peer`, the key its connection proved. `Err` means the
    /// stream goes unanswered and the caller drops its writer unshut.
    async fn exchange(
        &self,
        peer: VerifyKey,
        mut writer: impl AsyncWrite + Unpin,
        mut reader: impl AsyncRead + Unpin,
    ) -> io::Result<()> {
        let mut byte = [0u8; 1];
        bounded(reader.read_exact(&mut byte)).await?;
        let Some(request) = Request::decode(byte[0]) else {
            // An unknown tag changes nothing. SC1's pause requests (`3`, `4`) land here too until SC1
            // builds them: no pause rides in silently.
            return answer(&mut writer, Answer::BadRequest, &[]).await;
        };
        match request {
            // Always answered, held or not: a list grants nothing.
            Request::List => {
                // The encode is bounded by the catalog wire's own cap, which the reader also holds: a node
                // whose route table outgrew the wire fails here rather than writing a blob the reader cuts
                // short. It is this node's own configuration, so the reason stays on this side.
                let blob = self.catalog.encode().map_err(io::Error::other)?;
                answer(&mut writer, Answer::Done, &blob).await
            }
            Request::Stop => self.stop(peer, writer, reader).await,
        }
    }

    /// Answer a stop: [`Answer::NotYet`] while the first round runs, nothing at all to a key revoked since
    /// admission, else [`Answer::Done`] and the stop.
    async fn stop(
        &self,
        peer: VerifyKey,
        mut writer: impl AsyncWrite + Unpin,
        mut reader: impl AsyncRead + Unpin,
    ) -> io::Result<()> {
        // The hold first, then the revocations, with no await between them or before `Done`: the round's
        // fold is on disk a stat debounce before the hold opens, so once a request reads it open, the store
        // it asks next stats afresh and holds every revocation that round took. A held stop arms nothing,
        // so it can never cancel.
        if self.hold.is_held() {
            return answer(&mut writer, Answer::NotYet, &[]).await;
        }
        if self.revoked.is_revoked_key(&peer) {
            tracing::debug!(%peer, "control.serve stop refused: the key was revoked after admission");
            return Err(io::Error::other(
                "the caller's key was revoked after admission",
            ));
        }
        // Armed only once the byte has left this handler, since from then the caller may hold `Done` and
        // print `Stopped`. A write past the bound returns before the guard exists, so a stalled `Done`
        // stops nothing; a write that failed outright still arms, because the byte may have left before
        // the stream broke.
        let written = bounded(writer.write_all(&[Answer::Done.encode()])).await;
        if written
            .as_ref()
            .is_err_and(|error| error.kind() == io::ErrorKind::TimedOut)
        {
            return written;
        }
        let stopping = StopOnDrop {
            cancel: &self.cancel,
            source: &self.source,
            peer,
        };
        let answered = match written {
            Ok(()) => bounded(writer.shutdown()).await,
            Err(error) => Err(error),
        };
        // The node stops once the caller has closed its side, so its teardown cannot drop `Done` in flight.
        caller_closed(&mut reader).await;
        drop(stopping);
        answered
    }
}

impl Handler for Serve {
    // Member-only, with no safe public form: the marker keeps an open-gate pairing from ever being built.
    type Exposure = Never;

    async fn serve(
        &self,
        served: Served<Self>,
        writer: BoxWrite,
        reader: BoxRead,
    ) -> Result<(), ServeError> {
        // An `Err` returns the writer unshut, which tightbeam resets: an unanswered stream never reads as a
        // clean end.
        self.exchange(served.peer(), writer, reader)
            .await
            .map_err(Into::into)
    }
}

/// The stop an answered `Done` owes, fired when dropped: on the handler's own return, or when the handler's
/// future is dropped mid-wait (a live cut ending the session). Either way the caller's `Stopped` stays true.
struct StopOnDrop<'a> {
    /// The node's teardown token, cancelled on drop.
    cancel: &'a CancellationToken,
    /// Where the stop is noted, before the cancel.
    source: &'a StopSource,
    /// The key the connection proved, noted as the stop's source.
    peer: VerifyKey,
}

impl Drop for StopOnDrop<'_> {
    fn drop(&mut self) {
        // Noted before the cancel, as the socket stop does, so the run reads a wire stop and its key. On a
        // drop racing Ctrl-C this can note the wire stop first, which is true too: both asked.
        self.source.note(StopKind::Wire(self.peer));
        self.cancel.cancel();
    }
}

/// Wait for the caller's side to end after `Done`: its close after reading the answer, a broken stream,
/// or [`ACK_GRACE`], whichever is first. Read only to see it end; nothing read is kept, since the key is
/// the connection's. The cap bounds what a caller can make the node read on its way down.
async fn caller_closed(reader: &mut (impl AsyncRead + Unpin)) {
    let mut ignored = reader.take(CALLER_BYTES);
    let _ = tokio::time::timeout(ACK_GRACE, io::copy(&mut ignored, &mut io::sink())).await;
}

/// Write `answer` then `body`, and end the stream, all under [`REQUEST_DEADLINE`].
async fn answer(
    writer: &mut (impl AsyncWrite + Unpin),
    answer: Answer,
    body: &[u8],
) -> io::Result<()> {
    bounded(async {
        writer.write_all(&[answer.encode()]).await?;
        writer.write_all(body).await?;
        writer.shutdown().await
    })
    .await
}

/// Run `step` under [`REQUEST_DEADLINE`]; past it, a `TimedOut` error.
async fn bounded<T>(step: impl Future<Output = io::Result<T>>) -> io::Result<T> {
    tokio::time::timeout(REQUEST_DEADLINE, step)
        .await
        .unwrap_or_else(|_elapsed| {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "control.serve ran past its bound",
            ))
        })
}

/// How long `control.serve` waits for a stream's request, and then for each answer to leave. The route's own
/// bound, never the socket's: a member that admits a stream and says nothing, or grants no credit for the
/// answer, holds a task for this long and no longer.
pub const REQUEST_DEADLINE: Duration = Duration::from_secs(5);

/// How long the stopped node waits for the caller to close its side after `Done`, before it stops anyway.
/// The caller closes the moment it reads the answer, so on a live path this is one round trip; the bound
/// is for a caller that never closes, which can then delay the stop by this much and no more. A member may
/// stop the node outright, so the delay gives it nothing it did not already hold.
pub const ACK_GRACE: Duration = Duration::from_secs(2);

/// The most the stopped node reads from the caller while it waits for the close. The caller sends nothing
/// after its request, so any cap works; one that does send more than this ends the wait early, which can
/// cost only that caller its answer.
const CALLER_BYTES: u64 = 64;

/// The line a node stopped over `control.serve` prints: the name this node holds for the key that stopped
/// it and its short key, or the whole key when it holds no name for it. One of your devices is named as
/// yours first, whatever else the book saved the key under.
///
/// Any of your devices may stop any other, so this line on the stopped node's own stderr is the one trail
/// a stop leaves. It is built only from the key the connection proved, so nothing on it can come from the
/// caller's request, and a caller cannot claim to be another device.
pub fn stopped_by(contacts: &Contacts, peer: VerifyKey) -> String {
    // An admitted peer's key is one the transport proved, so it is always a usable key; the arm keeps the
    // whole key for one that somehow is not.
    let Ok(node) = peer.node_id() else {
        return format!("Stopped by {peer}.");
    };
    let mine = contacts
        .mine()
        .find(|(_, key)| **key == node)
        .map(|(label, _)| OwnDevice::from(label.clone()).to_string());
    match mine.or_else(|| contacts.saved_at(&node).map(|name| name.to_string())) {
        Some(name) => format!("Stopped by {name} ({}).", crate::credential::short(&node)),
        None => format!("Stopped by {node}."),
    }
}

/// A request on `control.serve`: one byte, no body, no version byte (the route's name is its version).
///
/// The codes are the founder's (W1a), fixed so SC1 adds its requests without renumbering: `3` and `4` are
/// SC1's pause and resume, refused as unknown until it builds them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Request {
    /// What this node serves: the catalog, after [`Answer::Done`].
    List,
    /// Stop this node.
    Stop,
}

impl Request {
    /// The request's byte.
    pub const fn encode(self) -> u8 {
        match self {
            Self::List => 1,
            Self::Stop => 2,
        }
    }

    /// The request `byte` names, or `None` for any other byte. Closed: no byte defaults to a request.
    pub const fn decode(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::List),
            2 => Some(Self::Stop),
            _ => None,
        }
    }
}

/// The answer to a `control.serve` request: one byte, before any body.
///
/// The codes are the founder's (W1a); `1` to `3` are SC1's pause answers, left free.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    /// Done: the catalog follows a list, and the node stops after a stop.
    Done,
    /// A stop before the run's first sync round has ended: ask again later.
    NotYet,
    /// The request was not one this node answers.
    BadRequest,
}

impl Answer {
    /// The answer's byte.
    pub const fn encode(self) -> u8 {
        match self {
            Self::Done => 0,
            Self::NotYet => 4,
            Self::BadRequest => 5,
        }
    }

    /// The answer `byte` names, or `None` for any other byte. Closed: no byte defaults to an answer.
    pub const fn decode(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::Done),
            4 => Some(Self::NotYet),
            5 => Some(Self::BadRequest),
            _ => None,
        }
    }
}

/// The first sync round of a run: [`finished`](Self::finished) lets a remote stop in.
///
/// A device that was stopped misses the revocations offered while it was down, and a revoked device that
/// keeps stopping it would keep it from ever folding its own revocation. So a run takes no remote stop
/// until its first round with your devices has ended, whatever that round found: a newer list, the same
/// list, no device answering within the round's bound, or nothing to ask on a machine that is not one of
/// your devices. A stop that waited for a newer list would leave such a machine never stoppable from
/// another device. A stop typed on the machine never passes the gate, so it is never held.
///
/// How long the hold lasts is the round's own bound: usually at most 20 s (5 s per device, 20 s in all).
/// When your devices refuse this machine because its date has passed or it was revoked, the round first
/// picks up its renewal, asking every device under `me` for 5 s each, then runs a second 20 s pass: at
/// worst 40 s plus 5 s per device under `me`, plus any wait for `home.lock`. Nothing caps the whole: a
/// cap would open the stop before the second pass, the one that can carry the revocation in that case.
#[derive(Debug)]
#[must_use = "a remote stop stays held until finished() is called"]
pub struct FirstRound(watch::Sender<bool>);

impl FirstRound {
    /// The round's half, and the [`Hold`] a stop reads.
    pub fn new() -> (Self, Hold) {
        // A watch rather than a bare flag: a request reads it without waiting, and a test can wait for the
        // round to end.
        let (finished, open) = watch::channel(false);
        (Self(finished), Hold(open))
    }

    /// Another [`Hold`] on this round, for a test that watches it from outside.
    #[cfg(any(test, feature = "test-support"))]
    pub fn hold(&self) -> Hold {
        Hold(self.0.subscribe())
    }

    /// The first round has ended: a remote stop is taken from here on. Taken by value, since a run has one
    /// first round.
    pub fn finished(self) {
        self.0.send_replace(true);
    }
}

/// Whether a run's first sync round still holds a remote stop. Read per request with `borrow`, never
/// awaited, so no request parks on it, and a [`FirstRound`] dropped before it finished stays held.
#[derive(Debug, Clone)]
pub struct Hold(watch::Receiver<bool>);

impl Hold {
    /// Whether the first round is still running.
    pub fn is_held(&self) -> bool {
        !*self.0.borrow()
    }

    /// Wait until the first round has ended; at once when it already has. A round dropped before it
    /// finished never opens, so this waits on. For tests, which watch the hold from outside.
    #[cfg(any(test, feature = "test-support"))]
    pub async fn opened(&self) {
        let mut open = self.0.clone();
        if open.wait_for(|open| *open).await.is_err() {
            core::future::pending::<()>().await;
        }
    }
}

#[cfg(test)]
#[path = "serve_tests.rs"]
mod serve_tests;
