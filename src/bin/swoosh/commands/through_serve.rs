//! Verbs that dial through a running `swoosh serve` rather than binding this home's key:
//! `forward <machine> <service> -`, and `speed`, which also follows its connection's path there.
//!
//! When `serve` answers on this home's control socket, the verb's stream is one Open there: this
//! process binds nothing, reads no key and asks no passphrase, and the resident presents this home's
//! standing (or the link typed as the machine). When no `serve` runs, the verb binds its own as before.
//! Once `serve` has answered, a failure is reported, never retried by an own bind.
//!
//! The lines a resident's outcome prints are the own bind's, so one line has one shape on both paths;
//! only a busy `serve`, a `serve` that stopped under the pipe, a different `serve` version and a reach
//! flag `serve` makes moot have lines of their own.

use core::cell::RefCell;
use core::pin::Pin;
use core::task::{Context, Poll};

use bifrost::{ConnInfo, NodeId, PathChanges, Refusal, WriteEnd};
use nauthy::{Link, Service};
use swoosh::contacts::Contacts;
use swoosh::escape::escaped_report;
use swoosh::node_client::{Connected, NodeClient, Opened, UidSocket};
use swoosh::peer::{Kind, Machine as PeerMachine};
use swoosh::peers::Hints;
use swoosh::serve::control_codec::{
    ControlError, Observation, OpenLane, OpenRead, OpenRefusal, OpenRequest, OpenWrite, PathRef,
    PeerRefusal,
};
use swoosh::transport::ReachArgs;
use tokio::io::{self, AsyncWrite};

use crate::commands::connect::{ConnectionLost, Machine, Stdin, Stdout, pump_stdio};
use crate::commands::machine;

/// Whether a run took the resident's path.
pub enum Routed {
    /// No `serve` answers here: the verb binds its own.
    OwnBind,
    /// The verb ran through `serve`, to this end.
    Ran(eyre::Result<()>),
}

/// A verb's dial, as the resident needs it.
pub struct Dial<'a> {
    /// The machine the verb dials.
    pub machine: &'a PeerMachine,
    /// The service it asks for.
    pub service: &'a Service,
    /// The link typed as the machine, if one was: the resident presents it as the slip.
    pub slip: Option<Link>,
    /// The verb's reach flags: `--peer` hints ride the Open; the rest cannot apply to a bind it does not
    /// make.
    pub reach: &'a ReachArgs,
    /// This home's book, to name the machine.
    pub contacts: &'a Contacts,
}

/// The `serve` at `home`'s control socket, with a connection to it checked and nothing sent, or `None`
/// when no `serve` answers here.
///
/// # Errors
///
/// The control socket cannot be trusted; never an own bind then.
pub async fn serve(home: &swoosh::home::Home) -> eyre::Result<Option<(UidSocket, Connected)>> {
    let socket = match UidSocket::resolve(home) {
        Ok(socket) => socket,
        Err(ControlError::NoResident) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    match socket.connected().await {
        Ok(connected) => Ok(Some((socket, connected))),
        Err(ControlError::NoResident) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// Run `dial` as a `forward <machine> <service> -` through the `serve` at `home`'s control socket when
/// one answers.
///
/// # Errors
///
/// The control socket cannot be trusted; never an own bind then.
pub async fn forward(home: &swoosh::home::Home, dial: Dial<'_>) -> eyre::Result<Routed> {
    let Some((socket, connected)) = serve(home).await? else {
        return Ok(Routed::OwnBind);
    };
    Ok(Routed::Ran(dial.forward(&socket, connected).await))
}

/// A stream the resident attached: the path it rode as it attached, the reference to observe it by
/// when the Open asked for one, and its two halves.
pub struct Stream {
    /// The connection's path report, read as the stream attached.
    pub info: ConnInfo,
    /// Present exactly when the Open was observed.
    pub reference: Option<PathRef>,
    /// The peer's bytes.
    pub read: OpenRead,
    /// The bytes toward the peer.
    pub write: OpenWrite,
}

impl Dial<'_> {
    async fn forward(mut self, socket: &UidSocket, connected: Connected) -> eyre::Result<()> {
        // Main: an ordinary pipe. Bulk is a fan-out's lane, Isolated a measurement's.
        let stream = self
            .open(socket, connected, OpenLane::Main, Observation::Unobserved)
            .await?;
        match pump_stdio(stream.write, stream.read, Stdin::open()?, Stdout::default()).await {
            Err(report) if report.is::<ConnectionLost>() => Err(self.cut(socket).await),
            ended => ended,
        }
    }

    /// Open the verb's one stream through `serve` on `connected`, on `lane`, asking for a reference to
    /// its connection when `observation` says so. Every outcome that is not a stream is the line the
    /// verb prints for it.
    ///
    /// # Errors
    ///
    /// A reach flag `serve` makes moot, more hints than one Open carries, the resident's or the peer's
    /// refusal, or a cut.
    pub async fn open(
        &mut self,
        socket: &UidSocket,
        connected: Connected,
        lane: OpenLane,
        observation: Observation,
    ) -> eyre::Result<Stream> {
        if let Some(moot) = Moot::first(self.reach) {
            return Err(moot.into());
        }
        let key = self.machine.key();
        let hints = Hints::new(
            self.reach
                .peer
                .iter()
                .filter(|hint| hint.node() == key)
                .flat_map(|hint| hint.addrs().iter().copied()),
        )?;
        let request = OpenRequest::new(key, hints, self.service.clone(), lane, self.slip.take())?;
        let request = match observation {
            Observation::Unobserved => request,
            Observation::Observed => request.observed(),
        };
        match connected.open(request).await {
            Ok(Opened::Attached {
                info,
                reference,
                read,
                write,
            }) => Ok(Stream {
                info,
                reference,
                read,
                write,
            }),
            Ok(Opened::Refused(refusal)) => Err(self.refused(refusal, socket).await),
            Ok(Opened::Error(reason)) => Err(escaped_report(eyre::eyre!(reason))),
            Err(ControlError::Version { .. }) => Err(Skew.into()),
            Err(error) => {
                tracing::debug!(%error, "an open through serve failed before its reply");
                Err(self.cut(socket).await)
            }
        }
    }

    /// The line a refusal prints: the own bind's for the same outcome, except `Busy` and `NotHere`.
    /// `serve` is asked its status only for an ended standing, whose remedy names this machine's key.
    async fn refused(&self, refusal: OpenRefusal, serve: &impl NodeClient) -> eyre::Report {
        match refusal {
            // No session to ask one of your devices why, so the line names no cause it cannot tell.
            OpenRefusal::Peer(PeerRefusal::NotAdmitted) => {
                machine::refused(self.machine, self.service, None)
            }
            OpenRefusal::Peer(refusal) => {
                escaped_report(bifrost::Error::Refused(Refusal::from(refusal)).into())
            }
            OpenRefusal::Unreachable(detail) => {
                escaped_report(bifrost::Error::Connect(detail.to_string().into()).into())
            }
            OpenRefusal::Timeout => {
                escaped_report(bifrost::Error::Connect("timed out".into()).into())
            }
            OpenRefusal::Broken(detail) | OpenRefusal::PeerUnreadable(detail) => {
                escaped_report(bifrost::Error::Stream(detail.to_string().into()).into())
            }
            OpenRefusal::Busy => Busy.into(),
            OpenRefusal::StandingEnded => {
                let this = match serve.status().await {
                    Ok(status) => Some(status.node_id),
                    Err(error) => {
                        tracing::debug!(%error, "serve's status for the ended standing's remedy failed");
                        None
                    }
                };
                StandingEnded(this).into()
            }
            OpenRefusal::NotHere => ThisMachine::of(self.machine).into(),
        }
    }

    /// The line a stream cut off prints: `serve`'s own when it no longer answers, else the cut-off's.
    async fn cut(&self, socket: &UidSocket) -> eyre::Report {
        self.cut_or(socket, ConnectionLost.into()).await
    }

    /// `serve`'s own line when it no longer answers, else `own`, the line the own bind prints for the
    /// same end.
    pub async fn cut_or(&self, socket: &UidSocket, own: eyre::Report) -> eyre::Report {
        let named = Machine::of(self.contacts, self.machine.key());
        after_a_cut(socket.status_attributed().await.map(drop), &named, own)
    }
}

/// The line for a cut-off stream, from what asking `serve` again gave: `serve`'s own line when nothing
/// answers there, else `own`. An answer that is not a status still counts as one: something listens, so
/// the cut was not `serve` going.
fn after_a_cut(
    asked: Result<(), ControlError>,
    machine: &Machine,
    own: eyre::Report,
) -> eyre::Report {
    match asked {
        Err(ControlError::NoResident | ControlError::Io(_) | ControlError::Timeout { .. }) => {
            ServeStopped(machine.to_string()).into()
        }
        _ => own,
    }
}

/// One stream through `serve`, as a session that hands out that stream once: what a verb written over a
/// session, such as `speed`'s measurement, runs on.
///
/// Through `serve`, [`peer`](bifrost::Session::peer) is the key the verb asked for, as claimed by the
/// process answering the socket. That process is checked to run as this user and to be the pid
/// `serve.lock` records, and neither check holds against a process running as this user, which can bind
/// the path and rewrite `serve.lock`; by own bind the transport proves the peer. The resident holds the
/// connection, so `wait_closed` never resolves and `close` ends nothing. `accept_bi` refuses, and so does
/// a second `open_bi`: `serve` gave one stream.
pub struct OneStream {
    peer: NodeId,
    info: ConnInfo,
    stream: RefCell<Option<(Upload, OpenRead)>>,
}

impl OneStream {
    /// The stream `serve` attached to `peer`, its path reading `info` as it attached.
    pub fn new(peer: NodeId, info: ConnInfo, read: OpenRead, write: OpenWrite) -> Self {
        Self {
            peer,
            info,
            stream: RefCell::new(Some((Upload(Some(write)), read))),
        }
    }
}

impl bifrost::Session for OneStream {
    type Write = Upload;
    type Read = OpenRead;

    fn peer(&self) -> NodeId {
        self.peer
    }

    async fn open_bi(&self) -> Result<(Self::Write, Self::Read), bifrost::Error> {
        self.stream
            .borrow_mut()
            .take()
            .ok_or(bifrost::Error::Closed)
    }

    async fn accept_bi(&self) -> Result<(Self::Write, Self::Read), bifrost::Error> {
        Err(bifrost::Error::Closed)
    }

    async fn wait_closed(&self) {
        core::future::pending().await
    }

    fn close(&self) {}

    /// The path as the stream attached. A verb that reports its path reads it from its observer, which
    /// asks `serve`; this cannot.
    fn conn_info(&self) -> ConnInfo {
        self.info.clone()
    }

    /// The path as the stream attached, as a path that never moves: only `serve` can tell it moved.
    fn path_changes(&self) -> PathChanges {
        PathChanges::fixed(self.info.path.clone())
    }
}

/// The write half of a [`OneStream`]'s stream: Data frames, and End at its `shutdown`. Aborted, or
/// dropped before `shutdown`, it closes the direction with no End, which `serve` passes on to the peer as
/// a reset. Its `delivered` never resolves: the word that the peer holds the upload is the read half's.
pub struct Upload(Option<OpenWrite>);

impl Upload {
    fn half(&mut self) -> io::Result<Pin<&mut OpenWrite>> {
        self.0
            .as_mut()
            .map(Pin::new)
            .ok_or_else(|| io::ErrorKind::BrokenPipe.into())
    }
}

impl AsyncWrite for Upload {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut().half() {
            Ok(half) => half.poll_write(cx, buf),
            Err(error) => Poll::Ready(Err(error)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut().half() {
            Ok(half) => half.poll_flush(cx),
            Err(error) => Poll::Ready(Err(error)),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut().half() {
            Ok(half) => half.poll_shutdown(cx),
            Err(error) => Poll::Ready(Err(error)),
        }
    }
}

impl WriteEnd for Upload {
    fn abort(&mut self) {
        if let Some(write) = self.0.take() {
            write.abort();
        }
    }

    /// Never resolves: through `serve` the word that the peer holds the upload is Landed, which arrives
    /// on the read half ([`OpenRead::landed`]), out of this half's reach. Pending forever is the answer
    /// the transport contract gives for a peer that never takes the bytes, so a caller's own bound ends
    /// the wait; any error here would claim a reset, a stopped reader or a lost session that did not
    /// happen. It writes no End, and it holds the half until the wait is dropped, so the direction ends
    /// as the caller left it: cleanly after its `shutdown`, else as a cut once the caller gives up.
    async fn delivered(self) -> io::Result<()> {
        let _held = self;
        core::future::pending().await
    }
}

/// A reach flag set while `serve` answers: it applies to a bind this run does not make.
#[derive(Debug, thiserror::Error)]
#[error(
    "{0} does not apply while swoosh serve runs here\n  Commands here connect through swoosh \
     serve.\n  Set it on swoosh serve, or stop swoosh serve and run this command again."
)]
pub struct Moot(&'static str);

impl Moot {
    /// The first reach flag set, in the order the line names them, both spellings.
    fn first(reach: &ReachArgs) -> Option<Self> {
        if reach.local {
            Some(Self("--local or SWOOSH_LOCAL"))
        } else if reach.relay.is_some() {
            Some(Self("--relay or SWOOSH_RELAY"))
        } else if reach.resolver.is_some() {
            Some(Self("--resolver or SWOOSH_RESOLVER"))
        } else {
            None
        }
    }
}

/// `serve`'s cap on the connections through it is full.
#[derive(Debug, thiserror::Error)]
#[error(
    "too many connections open through swoosh serve on this machine\n  Close one, or wait for one to \
     end, then try again."
)]
pub struct Busy;

/// `serve` stopped under a live pipe, or before it answered.
#[derive(Debug, thiserror::Error)]
#[error(
    "swoosh serve stopped here and ended the connection to {0}\n  Commands here connect through it \
     while it runs.\n  Run this command again to reconnect."
)]
pub struct ServeStopped(String);

/// The `serve` answering is another version of swoosh.
#[derive(Debug, thiserror::Error)]
#[error("swoosh serve on this machine is a different version\n  Restart it with this version.")]
pub struct Skew;

/// This home's standing has ended and `serve` could not renew it: the own bind's dead-badge line, with
/// the remedy keyed to this machine's key as `serve`'s status gives it, or the head alone when that
/// status cannot be read.
// The own bind's line names the badge's date too; reading it here can load the root key, which a run
// through `serve` never does, so the head says only that the badge has ended.
#[derive(Debug)]
pub struct StandingEnded(Option<NodeId>);

impl core::fmt::Display for StandingEnded {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(
            "this device's membership badge has ended, so a family-gated peer will refuse this dial",
        )?;
        match self.0 {
            Some(this) => write!(f, "; {}", swoosh::badge::remedy(this)),
            None => Ok(()),
        }
    }
}

impl core::error::Error for StandingEnded {}

/// The machine typed is this one: a usage error, exit 2.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct ThisMachine(String);

impl ThisMachine {
    /// The line for `machine`, as it was typed: its name, a key or a link.
    fn of(machine: &PeerMachine) -> Self {
        Self(match (machine.name(), machine.kind()) {
            (Some(name), _) => format!("{name} is this machine"),
            (None, Kind::Link) => "that link is for this machine".to_owned(),
            (None, _) => "that key is this machine's".to_owned(),
        })
    }
}

#[cfg(test)]
#[path = "through_serve_tests.rs"]
mod tests;
