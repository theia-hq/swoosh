//! Verbs that dial through a running `swoosh serve` rather than binding this home's key:
//! `forward <machine> <service> -`, `forward <machine> <service> <port>` and `proxy`, and `speed`, `ping`
//! and `status <machine>`, which also follow their connection's path there.
//!
//! When `serve` answers on this home's control socket, the verb's stream is one Open there: this
//! process binds nothing, reads no key and asks no passphrase, and the resident presents this home's
//! standing (or the link typed as the machine). When no `serve` runs, the verb binds its own as before.
//! Once `serve` has answered, a failure is reported, never retried by an own bind.
//!
//! A listener (`forward <port>`, `proxy`) makes one Open per local connection, each on a control
//! connection of its own, all on Bulk and none observed: it prints no path, so nothing would read a
//! reference, and holding one per pipe for hours would keep a reach slot and the control pool busy for
//! no reader. A pipe's outcome that every later Open would repeat ends the run with its line: `serve`
//! gone, under the pipe or at its Open (its lock free, or a `serve` of another version answering), the
//! machine's `NotAdmitted`, an ended standing, or the machine being this one. Any other (`Busy`, the
//! machine unavailable or unreachable, a cut) ends that pipe alone, and goes to the log.
//!
//! The lines a resident's outcome prints are the own bind's, so one line has one shape on both paths;
//! only a busy `serve`, a `serve` that stopped under the pipe, a different `serve` version and a reach
//! flag `serve` makes moot have lines of their own.

use core::cell::RefCell;
use core::ops::ControlFlow;
use core::pin::Pin;
use core::task::{Context, Poll};
use std::rc::Rc;

use bifrost::{ConnInfo, NodeId, PathChanges, Refusal, WriteEnd};
use nauthy::{Link, Service};
use swoosh::contacts::Contacts;
use swoosh::escape::escaped_report;
use swoosh::home::ResidentPresence;
use swoosh::node_client::{Connected, NodeClient, Opened, UidSocket};
use swoosh::observation::{Observed, Observer, PathSource, Receipt};
use swoosh::peer::{Kind, Machine as PeerMachine};
use swoosh::peers::Hints;
use swoosh::serve::control_codec::{
    ControlError, Observation, OpenLane, OpenRead, OpenRefusal, OpenRequest, OpenWrite, PathRef,
    PeerRefusal,
};
use swoosh::transport::ReachArgs;
use tokio::io::{self, AsyncWrite, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

use crate::commands::connect::{
    self, ConnectionLost, MAX_PIPES, Machine, Stdin, Stdout, accept_each, pump_stdio,
};
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

/// Run `dial` as a `forward <machine> <service> <port>` through the `serve` at `home`'s control socket
/// when one answers.
///
/// # Errors
///
/// The control socket cannot be trusted; never an own bind then.
pub async fn forward_port(
    home: &swoosh::home::Home,
    dial: Dial<'_>,
    port: u16,
) -> eyre::Result<Routed> {
    let Some((socket, connected)) = serve(home).await? else {
        return Ok(Routed::OwnBind);
    };
    Ok(Routed::Ran(
        dial.forward_port(&socket, connected, port).await,
    ))
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
    async fn forward(self, socket: &UidSocket, connected: Connected) -> eyre::Result<()> {
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
        &self,
        socket: &UidSocket,
        connected: Connected,
        lane: OpenLane,
        observation: Observation,
    ) -> eyre::Result<Stream> {
        match self.attach(socket, connected, lane, observation).await {
            Ok(stream) => Ok(stream),
            Err(unattached) => Err(self.unattached(unattached, socket).await),
        }
    }

    /// [`open`](Self::open), with the resident's refusal kept typed for a verb that prints its own line
    /// for it.
    async fn attach(
        &self,
        socket: &UidSocket,
        connected: Connected,
        lane: OpenLane,
        observation: Observation,
    ) -> Result<Stream, Unattached> {
        if let Some(moot) = Moot::first(self.reach) {
            return Err(Unattached::Failed(moot.into()));
        }
        let key = self.machine.key();
        let hints = Hints::new(
            self.reach
                .peer
                .iter()
                .filter(|hint| hint.node() == key)
                .flat_map(|hint| hint.addrs().iter().copied()),
        )
        .map_err(|error| Unattached::Failed(error.into()))?;
        // Cloned, never taken: a listener opens once per pipe, and an Open without the slip is refused
        // by a peer that admits only the link.
        let slip = Option::clone(&self.slip);
        let request = OpenRequest::new(key, hints, self.service.clone(), lane, slip)
            .map_err(|error| Unattached::Failed(error.into()))?;
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
            Ok(Opened::Refused(refusal)) => Err(Unattached::Refused(refusal)),
            Ok(Opened::Error(reason)) => {
                Err(Unattached::Failed(escaped_report(eyre::eyre!(reason))))
            }
            Err(ControlError::Version { .. }) => Err(Unattached::Failed(Skew.into())),
            Err(error) => {
                tracing::debug!(%error, "an open through serve failed before its reply");
                Err(Unattached::Failed(self.cut(socket).await))
            }
        }
    }

    /// The line an Open that attached nothing prints, when the verb prints none of its own for it.
    pub async fn unattached(
        &self,
        unattached: Unattached,
        serve: &impl NodeClient,
    ) -> eyre::Report {
        match unattached {
            Unattached::Refused(refusal) => self.refused(refusal, serve).await,
            Unattached::Failed(report) => report,
        }
    }

    /// Open the verb's one stream through `serve` on `connected`, on `lane`, observed: the stream as a
    /// session, and the observer that follows its connection through `socket`, read from the Attached
    /// report on.
    ///
    /// # Errors
    ///
    /// As [`open`](Self::open), with the resident's refusal kept typed.
    pub async fn observed(
        &self,
        socket: &Rc<UidSocket>,
        connected: Connected,
        lane: OpenLane,
    ) -> Result<(OneStream, Observer), Unattached> {
        let stream = self
            .attach(socket, connected, lane, Observation::Observed)
            .await?;
        let Some(reference) = stream.reference else {
            return Err(Unattached::Failed(eyre::eyre!(
                "internal: an observed open through serve came back without its reference"
            )));
        };
        let observer = Observer::new(
            Receipt::new(reference, Rc::clone(socket)),
            stream.info.clone(),
        );
        let session = OneStream::new(self.machine.key(), stream.info, stream.read, stream.write);
        Ok((session, observer))
    }

    /// Prove that the peer admits a listener's Open before its start lines print, so a refusal is one
    /// line and a non-zero exit rather than a listener that refuses every connection. The stream is
    /// ended with End, so the peer reads a clean end of an empty upload, never a reset.
    ///
    /// # Errors
    ///
    /// As [`open`](Self::open), or the End could not be written.
    pub async fn admit(&self, socket: &UidSocket, connected: Connected) -> eyre::Result<()> {
        let mut stream = self
            .open(socket, connected, LISTENER_LANE, Observation::Unobserved)
            .await?;
        match stream.write.shutdown().await {
            Ok(()) => Ok(()),
            Err(error) => Err(self.cut_or(socket, error.into()).await),
        }
    }

    /// One listener pipe's Open, on a control connection of its own: a [`Connected`] carries one Open
    /// and is spent by it.
    ///
    /// # Errors
    ///
    /// Why it attached nothing, sorted by what that does to the run ([`Unpiped`]).
    pub async fn pipe(&self, socket: &UidSocket) -> Result<Stream, Unpiped> {
        let connected = match socket.connected().await {
            Ok(connected) => connected,
            Err(ControlError::NoResident) if lock_free(socket).await => {
                return Err(Unpiped::of(Unattached::Failed(self.serve_stopped())));
            }
            Err(error) => return Err(Unpiped::of(Unattached::Failed(error.into()))),
        };
        match self
            .attach(socket, connected, LISTENER_LANE, Observation::Unobserved)
            .await
        {
            Ok(stream) => Ok(stream),
            // The run's `serve` answered its admission in this version, so a `serve` answering in
            // another is a restarted one: the run's is gone.
            Err(Unattached::Failed(report)) if report.is::<Skew>() => {
                Err(Unpiped::of(Unattached::Failed(self.serve_stopped())))
            }
            Err(unattached) => Err(Unpiped::of(unattached)),
        }
    }

    /// `forward <port>` through `serve`: admit, bind the local port, say so as the own bind does, then
    /// carry each local connection.
    async fn forward_port(
        &self,
        socket: &UidSocket,
        connected: Connected,
        port: u16,
    ) -> eyre::Result<()> {
        self.admit(socket, connected).await?;
        raise_open_files();
        let listener = TcpListener::bind(("127.0.0.1", port)).await?;
        connect::forwarding(
            self.service,
            &Machine::of(self.contacts, self.machine.key()),
            port,
        );
        Err(self.carry_each(socket, listener).await)
    }

    /// Carry each connection `listener` accepts over its own Open, at most [`MAX_PIPES`] at once, until
    /// a pipe ends the run ([`Unpiped::Ends`], or `serve` gone under it): the line the run ends with.
    pub async fn carry_each(&self, socket: &UidSocket, listener: TcpListener) -> eyre::Report {
        accept_each(listener, MAX_PIPES, |tcp| self.carry(socket, tcp)).await
    }

    /// Carry one local connection over its own Open, both ways. A failure that is the pipe's own goes
    /// to the log, as the own bind's does, and the listener stays up.
    async fn carry(&self, socket: &UidSocket, tcp: TcpStream) -> ControlFlow<eyre::Report> {
        let stream = match self.pipe(socket).await {
            Ok(stream) => stream,
            Err(Unpiped::Ends(unattached)) => {
                return ControlFlow::Break(self.unattached(unattached, socket).await);
            }
            Err(Unpiped::Pipe(unattached)) => {
                let error = self.unattached(unattached, socket).await;
                tracing::warn!("connection failed: {error:#}");
                return ControlFlow::Continue(());
            }
        };
        if let Err(error) = splice(tcp, stream).await {
            // A pipe cut under it may be `serve` stopping: asked now, so the run ends here rather than
            // at the next connection's Open.
            if let Some(stopped) = self.stopped(socket).await {
                return ControlFlow::Break(stopped);
            }
            tracing::warn!("connection failed: {error:#}");
        }
        ControlFlow::Continue(())
    }

    /// The line the run ends with when `serve` is gone.
    fn serve_stopped(&self) -> eyre::Report {
        ServeStopped(Machine::of(self.contacts, self.machine.key()).to_string()).into()
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
        self.stopped(socket).await.unwrap_or(own)
    }

    /// `serve`'s own line when it is gone, asked after a run broke: `None` while anything answers, or
    /// stalls, there, and the break is the run's own. The ask is bounded by [`STOPPED_ASK`], so a
    /// resident that accepts and stalls cannot hold a failed run's exit.
    pub async fn stopped(&self, socket: &UidSocket) -> Option<eyre::Report> {
        let named = Machine::of(self.contacts, self.machine.key());
        let asked = match tokio::time::timeout(STOPPED_ASK, socket.status_attributed()).await {
            Ok(asked) => asked.map(drop),
            Err(_elapsed) => Err(ControlError::Timeout {
                phase: "status after a cut",
            }),
        };
        let gone = serve_gone(asked, &named)?;
        lock_free(socket).await.then(|| gone.into())
    }
}

/// Whether `serve.lock` is free, so a refused connect means `serve` is gone. A refused connect alone
/// does not: on macOS a live `serve` whose accept queue is full refuses one too, while it holds the
/// lock. A held lock, a probe that failed or one past [`STOPPED_ASK`] shows nothing gone.
async fn lock_free(socket: &UidSocket) -> bool {
    match tokio::time::timeout(STOPPED_ASK, socket.resident_presence()).await {
        Ok(Ok(presence)) => presence == ResidentPresence::Free,
        Ok(Err(error)) => {
            tracing::debug!(%error, "serve.lock could not be probed after a refused connect");
            false
        }
        Err(_elapsed) => false,
    }
}

/// Raise this process's open-file limit for a listener through `serve`: each pipe holds two
/// descriptors, its local connection and its control connection, so [`MAX_PIPES`] of them pass the
/// limit macOS starts a process with. A run that cannot raise it still listens, with fewer pipes.
pub fn raise_open_files() {
    if let Err(error) = swoosh::serve::raise_open_files() {
        tracing::warn!(%error, "could not raise the open-file limit");
    }
}

/// How long a run that broke waits to learn whether `serve` is gone. A resident that is there answers
/// its status in a local round trip; one that is gone refuses the connection at once.
const STOPPED_ASK: core::time::Duration = core::time::Duration::from_secs(1);

/// `serve`'s own line when asking it again showed it gone: no resident, or the connection refused.
/// Anything else, an answer that is not a status, a reset, a stall, says something is there, so the
/// break was not `serve` stopping and the line must not claim it did.
fn serve_gone(asked: Result<(), ControlError>, machine: &Machine) -> Option<ServeStopped> {
    match asked {
        Err(ControlError::NoResident) => Some(ServeStopped(machine.to_string())),
        _ => None,
    }
}

/// Why an Open through `serve` attached no stream: the resident's typed refusal, which a probe verb
/// prints its own bind's line for, or the line for anything else.
pub enum Unattached {
    /// The resident or the peer refused the Open.
    Refused(OpenRefusal),
    /// The Open failed some other way: the line it prints.
    Failed(eyre::Report),
}

/// The lane a listener's Opens ride: its pipes are a fan-out, so they never take the slots the person's
/// other traffic on Main needs.
const LISTENER_LANE: OpenLane = OpenLane::Bulk;

/// Why a listener pipe's Open attached no stream, sorted by what it does to the run.
pub enum Unpiped {
    /// Load or a path fault, which the next connection can pass: that pipe ends, the listener stays up.
    Pipe(Unattached),
    /// An outcome every later Open would repeat: the run ends with its line, after a `proxy` client's
    /// answer, and never falls back to an own bind.
    Ends(Unattached),
}

impl Unpiped {
    /// Sort `unattached`. `serve` gone finds no `serve` for any later Open. `NotAdmitted` is a ruling on
    /// this machine (a revoke or a pause) that the wire says not to retry, so listening on would refuse
    /// every connection. An ended standing's remedy is the person's, and the own bind ends the same way
    /// when the lease end cuts its session. `NotHere` belongs to the fixed request, so it repeats.
    fn of(unattached: Unattached) -> Self {
        let ends = match &unattached {
            Unattached::Refused(refusal) => match refusal {
                OpenRefusal::Peer(PeerRefusal::NotAdmitted)
                | OpenRefusal::StandingEnded
                | OpenRefusal::NotHere => true,
                OpenRefusal::Peer(PeerRefusal::BadRequest(_) | PeerRefusal::Unavailable(_))
                | OpenRefusal::PeerUnreadable(_)
                | OpenRefusal::Unreachable(_)
                | OpenRefusal::Timeout
                | OpenRefusal::Broken(_)
                | OpenRefusal::Busy => false,
            },
            // A cut before the reply whose ask found `serve` gone, or no `serve` to connect to.
            Unattached::Failed(report) => report.is::<ServeStopped>(),
        };
        if ends {
            Self::Ends(unattached)
        } else {
            Self::Pipe(unattached)
        }
    }
}

/// Carry `tcp` over `stream` both ways until both ends close. An upload that carried a byte is whole
/// only on Landed, so the pipe waits for it, with no clock of its own: a peer that stops answering ends
/// the stream when the transport gives up on it.
async fn splice(mut tcp: TcpStream, stream: Stream) -> eyre::Result<()> {
    let Stream {
        mut read,
        mut write,
        ..
    } = stream;
    let (up, _down) =
        io::copy_bidirectional(&mut tcp, &mut io::join(&mut read, &mut write)).await?;
    if up > 0 {
        read.landed().await?;
    }
    Ok(())
}

/// A run through `serve` that failed after its Open attached, its error already printed by [`failed`]:
/// the composition root exits 1 and prints nothing more.
#[derive(Debug, thiserror::Error)]
#[error("the run's error was printed before its path was read")]
pub struct Reported;

/// How long past its spacing a failed run's Finish may take before the run exits without it. The run
/// prints no path, so nothing waits on the reply; a resident that accepts the query and stalls lets the
/// reference go at the end of its retention instead.
const FAILED_FINISH_GRACE: core::time::Duration = core::time::Duration::from_secs(1);

/// End a run through `serve` that failed after its Open attached: print `report` on `err` as the
/// composition root prints a run's error, then Finish `observer`, in this task, before the process
/// exits. The error never waits on a reading it does not show, and the resident lets the reference go
/// now rather than at the end of its retention. The Finish gets what is left of its spacing plus
/// [`FAILED_FINISH_GRACE`], and is dropped past that. Returns [`Reported`].
pub async fn failed<P: PathSource>(
    report: eyre::Report,
    observer: Observer<P>,
    err: &mut impl std::io::Write,
) -> eyre::Report {
    crate::print_error(&report, err);
    match observer.finish_within(FAILED_FINISH_GRACE).await {
        Some(observed) => log_path(observed),
        None => tracing::debug!("the failed run's Finish passed its bound and was dropped"),
    }
    Reported.into()
}

/// End a run through `serve` whose result is `ended`, its own lines already printed: a failure as
/// [`failed`] ends one, a success once its observation is Finished, so no exit leaves the reference to
/// the resident's retention.
pub async fn ended<P: PathSource>(
    ended: eyre::Result<()>,
    observer: Observer<P>,
    err: &mut impl std::io::Write,
) -> eyre::Result<()> {
    match ended {
        Ok(()) => {
            log_path(observer.finish().await);
            Ok(())
        }
        Err(report) => Err(failed(report, observer, err).await),
    }
}

/// Log the observation of a run through `serve` that prints no path: its own line is what it prints.
pub fn log_path(observed: Observed) {
    if let Some(earlier) = &observed.earlier {
        tracing::debug!(%earlier, "a sample of the run's path failed");
    }
    if let Err(error) = &observed.last {
        tracing::debug!(%error, "the run's final path could not be read");
    }
}

/// The path text a run through `serve` prints, from its final observation, the Finish's: `None` when
/// that failed, and `err` then carries a warning while the run's own result and exit stay as they are.
/// A sample that failed earlier is never shown: it goes to the log, at debug.
///
/// # Errors
///
/// The warning could not be written.
pub fn final_path(
    observed: Observed,
    err: &mut impl std::io::Write,
) -> std::io::Result<Option<ConnInfo>> {
    if let Some(earlier) = &observed.earlier {
        tracing::debug!(%earlier, "a sample of the run's path failed");
    }
    match observed.last {
        Ok(info) => Ok(Some(info)),
        Err(error) => {
            tracing::debug!(%error, "the run's final path could not be read");
            writeln!(err, "warning: could not read the path of this run")?;
            Ok(None)
        }
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
pub(crate) mod tests;
