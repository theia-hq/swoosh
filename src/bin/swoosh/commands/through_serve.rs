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
//! machine unavailable or unreachable, a stream broken as it opened) ends that pipe alone: it goes to the
//! log, and the first of a run of them to a [`PipeFailures`] warning, as by own bind. A pipe that attached
//! is carried, whatever ends it: the log alone.
//!
//! The lines a resident's outcome prints are the own bind's, so one line has one shape on both paths;
//! only a busy `serve`, a `serve` that stopped under the pipe, a different `serve` version and a reach
//! flag `serve` makes moot have lines of their own.

use core::ops::ControlFlow;
use std::collections::HashMap;

use bifrost::{ConnInfo, NodeId, Refusal};
use nauthy::{Link, Service};
use swoosh::contacts::Contacts;
use swoosh::escape::{Escaped, escaped_report};
use swoosh::node_client::{Connected, NodeClient, UidSocket};
use swoosh::observation::{Follow, Observed};
use swoosh::peer::{Kind, Machine as PeerMachine};
use swoosh::peers::{Hints, HintsError};
use swoosh::serve::control_codec::{
    ControlError, Observation, OpenLane, OpenRead, OpenRefusal, OpenWrite, PeerRefusal,
};
use swoosh::streams::{Ask, Opened, Resident, Unopened};
use swoosh::transport::ReachArgs;
use tokio::io::{self, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

use crate::commands::connect::{
    self, ConnectionLost, Failure, MAX_PIPES, Machine, PipeFailures, Stdin, Stdout, accept_each,
    pump_stdio,
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

/// Refuse a reach flag `serve` makes moot before a verb's local act, when `serve` answers here: the
/// act would land and its exchange would refuse after it. With no reach flag set the socket is not
/// probed.
///
/// # Errors
///
/// The flag's line, or the control socket cannot be trusted.
pub async fn refuse_moot(home: &swoosh::home::Home, reach: &ReachArgs) -> eyre::Result<()> {
    let Some(moot) = Moot::first(reach) else {
        return Ok(());
    };
    match serve(home).await? {
        Some(_) => Err(moot.into()),
        None => Ok(()),
    }
}

/// The `--peer` addresses as each machine's hints, by its key, checked before anything is read or
/// written: the addresses typed for one machine go to its Opens alone.
///
/// # Errors
///
/// [`CrowdedHints`] past the addresses one Open carries for a machine, or [`UnusableHint`] for one no
/// machine can be reached at: each a usage error.
pub fn hints(reach: &ReachArgs) -> eyre::Result<HashMap<NodeId, Hints>> {
    reach.reject_crowded_hints()?;
    let mut addrs: HashMap<NodeId, Vec<core::net::SocketAddr>> = HashMap::new();
    for hint in &reach.peer {
        addrs
            .entry(hint.node())
            .or_default()
            .extend_from_slice(hint.addrs());
    }
    addrs
        .into_iter()
        .map(|(key, addrs)| match Hints::new(addrs) {
            Ok(hints) => Ok((key, hints)),
            Err(HintsError::Unusable) => Err(UnusableHint.into()),
            Err(error) => Err(error.into()),
        })
        .collect()
}

/// A `--peer` address that is never a machine's endpoint: a usage error, exit 2.
#[derive(Debug, thiserror::Error)]
#[error("--peer or SWOOSH_PEER gives an address no machine can be reached at")]
pub struct UnusableHint;

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

/// A stream the resident attached: the path it rode as it attached, and its two halves as the socket
/// gives them.
pub type Stream = Opened<OpenWrite, OpenRead>;

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
        let ask = self.ask(lane)?;
        match Resident::attach(connected, &ask, observation).await {
            Ok((stream, _reference)) => Ok(stream),
            Err(unopened) => Err(self.unopened(unopened, socket).await),
        }
    }

    /// The Open this dial makes on `lane`, or the line for a reach flag `serve` makes moot or for more
    /// hints than one Open carries.
    pub(crate) fn ask(&self, lane: OpenLane) -> Result<Ask, Unattached> {
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
        Ok(Ask {
            peer: key,
            hints,
            service: self.service.clone(),
            lane,
            // Cloned, never taken: a listener opens once per pipe, and an Open without the slip is
            // refused by a peer that admits only the link.
            slip: Option::clone(&self.slip),
        })
    }

    /// What an Open that attached nothing means to this dial: the resident's or the peer's refusal kept
    /// typed, else the line it prints. A control connection that failed before its reply is `serve`'s
    /// own line when `serve` is gone, else a cut. A reply that never came is [`Unresponsive`] only when
    /// `serve` then fails a status too: a slow machine behind a `serve` that answers is never read as
    /// `serve` stalled.
    pub(crate) async fn unopened(&self, unopened: Unopened, socket: &UidSocket) -> Unattached {
        match unopened {
            Unopened::Refused(refusal) => Unattached::Refused(refusal),
            Unopened::ServeError(reason) => Unattached::Failed(escaped_report(eyre::eyre!(reason))),
            Unopened::Skew => Unattached::Failed(Skew.into()),
            Unopened::ServeGone => Unattached::Failed(self.serve_stopped()),
            Unopened::Malformed(malformed) => Unattached::Failed(malformed.into()),
            Unopened::Control(error @ ControlError::Timeout { .. }) => {
                tracing::debug!(%error, "an open through serve got no reply in time");
                if socket.stalled().await {
                    Unattached::Failed(Unresponsive.into())
                } else {
                    Unattached::Failed(self.cut(socket).await)
                }
            }
            // A socket that cannot be trusted keeps its own error, never a cut's.
            Unopened::Control(error @ ControlError::Untrusted { .. }) => {
                Unattached::Failed(error.into())
            }
            Unopened::Control(error) => {
                tracing::debug!(%error, "an open through serve failed before its reply");
                Unattached::Failed(self.cut(socket).await)
            }
            // The own bind's outcomes, which an Open through `serve` never gives.
            Unopened::Own(error) => Unattached::Failed(error.into()),
            Unopened::Home(report) => Unattached::Failed(report),
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
        let connected = self.connect(socket).await.map_err(Unpiped::of)?;
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

    /// A control connection of its own for one Open: a refused connect with `serve.lock` free is `serve`
    /// gone, its own line. A socket that cannot be trusted keeps its own error, never a cut's. Any other
    /// failure reads as an Open's that got no reply, so a live `serve` whose accept queue is full or that
    /// stalled says what an Open to it says.
    async fn connect(&self, socket: &UidSocket) -> Result<Connected, Unattached> {
        match socket.connected().await {
            Ok(connected) => Ok(connected),
            Err(ControlError::NoResident) if socket.lock_free().await => {
                Err(Unattached::Failed(self.serve_stopped()))
            }
            Err(error @ ControlError::Untrusted { .. }) => Err(Unattached::Failed(error.into())),
            Err(error) => Err(self.unopened(Unopened::Control(error), socket).await),
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
        let failures = PipeFailures::new(self.machine, std::io::stderr());
        Err(self.carry_each(socket, listener, &failures).await)
    }

    /// Carry each connection `listener` accepts over its own Open, at most [`MAX_PIPES`] at once, until
    /// a pipe ends the run ([`Unpiped::Ends`], or `serve` gone under it): the line the run ends with.
    pub async fn carry_each(
        &self,
        socket: &UidSocket,
        listener: TcpListener,
        failures: &PipeFailures<impl std::io::Write>,
    ) -> eyre::Report {
        accept_each(listener, MAX_PIPES, |tcp| self.carry(socket, tcp, failures)).await
    }

    /// Carry one local connection over its own Open, both ways. A failure that is the pipe's own goes
    /// to `failures`, as the own bind's does, and the listener stays up.
    async fn carry(
        &self,
        socket: &UidSocket,
        tcp: TcpStream,
        failures: &PipeFailures<impl std::io::Write>,
    ) -> ControlFlow<eyre::Report> {
        let stream = match self.pipe(socket).await {
            Ok(stream) => stream,
            Err(Unpiped::Ends(unattached)) => {
                return ControlFlow::Break(self.unattached(unattached, socket).await);
            }
            Err(Unpiped::Pipe(unattached)) => {
                let failure = unattached.failure();
                failures.failed(failure, &self.unattached(unattached, socket).await);
                return ControlFlow::Continue(());
            }
        };
        failures.carried();
        if let Err(error) = splice(tcp, stream).await {
            // A pipe cut under it may be `serve` stopping: asked now, so the run ends here rather than
            // at the next connection's Open.
            if let Some(stopped) = self.stopped(socket).await {
                return ControlFlow::Break(stopped);
            }
            // A pipe that opened is carried, whatever ends it: the log alone.
            tracing::warn!("connection failed: {:#}", escaped_report(error));
        }
        ControlFlow::Continue(())
    }

    /// The line the run ends with when `serve` is gone.
    pub(crate) fn serve_stopped(&self) -> eyre::Report {
        self.stopped_line().into()
    }

    /// [`serve_stopped`](Self::serve_stopped)'s line, typed, for a verb that words it further.
    pub(crate) fn stopped_line(&self) -> ServeStopped {
        ServeStopped(Machine::of(self.contacts, self.machine.key()).to_string())
    }

    /// The line a refusal prints: the own bind's for the same outcome, except `Busy` and `NotHere`.
    /// `serve` is asked its status only for an ended standing, whose remedy names this machine's key.
    pub(crate) async fn refused(
        &self,
        refusal: OpenRefusal,
        serve: &impl NodeClient,
    ) -> eyre::Report {
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
    /// stalls, there, and the break is the run's own, so the line never claims `serve` stopped when it
    /// did not. The ask is bounded ([`UidSocket::gone`]), so a resident that accepts and stalls cannot
    /// hold a failed run's exit.
    pub async fn stopped(&self, socket: &UidSocket) -> Option<eyre::Report> {
        let named = Machine::of(self.contacts, self.machine.key());
        socket
            .gone()
            .await
            .then(|| ServeStopped(named.to_string()).into())
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

/// Why an Open through `serve` attached no stream: the resident's typed refusal, which a probe verb
/// prints its own bind's line for, or the line for anything else.
pub enum Unattached {
    /// The resident or the peer refused the Open.
    Refused(OpenRefusal),
    /// The Open failed some other way: the line it prints.
    Failed(eyre::Report),
}

impl Unattached {
    /// What a listener's warning says of this failed Open, by the same rows as the own bind's. `None`
    /// only for an outcome that ends the run, which never asks.
    pub fn failure(&self) -> Option<Failure> {
        match self {
            Self::Refused(OpenRefusal::Peer(refusal)) => {
                Some(Failure::refused(&Refusal::from(refusal.clone())))
            }
            Self::Refused(OpenRefusal::Unreachable(_) | OpenRefusal::Timeout) => {
                Some(Failure::Unreachable)
            }
            Self::Refused(OpenRefusal::Broken(detail)) => Some(Failure::Interrupted(Some(
                Escaped(detail.as_str()).to_string(),
            ))),
            // A refusal this build cannot read carries no detail the person can use.
            Self::Refused(OpenRefusal::PeerUnreadable(_)) => Some(Failure::Interrupted(None)),
            Self::Refused(OpenRefusal::Busy) => Some(Failure::Busy),
            Self::Refused(OpenRefusal::StandingEnded | OpenRefusal::NotHere) => None,
            // A stream that failed to open, as by own bind: the resident's error reply, a control
            // connection that failed or was cut before its reply. Its reason is the log's.
            Self::Failed(_) => Some(Failure::Interrupted(None)),
        }
    }
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

/// End a run that failed after its stream attached: print `report` on `err` as the composition root
/// prints a run's error, then Finish `observer`, in this task, before the process exits. The error never
/// waits on a reading it does not show, and through `serve` the resident lets the reference go now
/// rather than at the end of its retention; by own bind the reading is the session's, at once. The Finish gets what is left of its spacing plus
/// [`FAILED_FINISH_GRACE`], and is dropped past that. Returns [`Reported`].
pub async fn failed(
    report: eyre::Report,
    observer: impl Follow,
    err: &mut impl std::io::Write,
) -> eyre::Report {
    crate::print_error(&report, err);
    match observer.finish_within(FAILED_FINISH_GRACE).await {
        Some(observed) => log_path(observed),
        None => tracing::debug!("the failed run's Finish passed its bound and was dropped"),
    }
    Reported.into()
}

/// End a run whose result is `ended`, its own lines already printed: a failure as
/// [`failed`] ends one, a success once its observation is Finished, so no exit leaves the reference to
/// the resident's retention.
pub async fn ended(
    ended: eyre::Result<()>,
    observer: impl Follow,
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

/// A reach flag set while `serve` answers: it applies to a bind this run does not make.
#[derive(Debug, thiserror::Error)]
#[error(
    "{0} does not apply while swoosh serve runs here\n  Commands here connect through swoosh \
     serve.\n  Set it on swoosh serve, or stop swoosh serve and run this command again."
)]
pub struct Moot(&'static str);

impl Moot {
    /// The first reach flag set, in the order the line names them, both spellings.
    pub(crate) fn first(reach: &ReachArgs) -> Option<Self> {
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

/// `serve` is there and took no connection, or gave no reply in time.
#[derive(Debug, thiserror::Error)]
#[error("swoosh serve on this machine did not answer\n  Restart it.")]
pub struct Unresponsive;

/// `serve` stopped under a live pipe, or before it answered.
#[derive(Debug, thiserror::Error)]
#[error(
    "swoosh serve stopped here and ended the connection to {0}\n  Commands here connect through it \
     while it runs.\n  Run this command again to reconnect."
)]
pub struct ServeStopped(String);

/// `serve` stopped under a root act's exchange with `machine`, after the act landed: no rerun is
/// advised, since the act is done and the started `serve` asks your devices itself.
#[derive(Debug, thiserror::Error)]
#[error(
    "swoosh serve stopped here and ended the connection to {0}\n  Commands here connect through it \
     while it runs.\n  Start it again; it asks your devices as it starts."
)]
pub struct StoppedAfterAct(pub(crate) String);

/// `serve` stopped under a `send` after at least one file printed `sent`: a bare rerun would send those
/// again, so the line says what is left.
#[derive(Debug, thiserror::Error)]
pub enum StoppedAfterSent {
    /// Files remain unsent: the rerun leaves out the ones already sent.
    #[error(
        "swoosh serve stopped here and ended the connection to {0}\n  Commands here connect through it \
         while it runs.\n  Run this command again to reconnect, without the files already marked `sent`."
    )]
    FilesLeft(String),
    /// Every file printed `sent`: nothing is left to send, so no rerun is advised.
    #[error(
        "swoosh serve stopped here and ended the connection to {0}\n  Commands here connect through it \
         while it runs.\n  Every file was marked `sent`."
    )]
    AllSent(String),
}

impl ServeStopped {
    /// The line for the connection to `machine`, as a line names it.
    pub(crate) fn to(machine: impl core::fmt::Display) -> Self {
        Self(machine.to_string())
    }

    /// This stop, met by a `send` with files still unsent after at least one printed `sent`.
    pub(crate) fn after_sent(self) -> StoppedAfterSent {
        StoppedAfterSent::FilesLeft(self.0)
    }

    /// This stop, met by a `send` after every one of its files printed `sent`.
    pub(crate) fn after_all_sent(self) -> StoppedAfterSent {
        StoppedAfterSent::AllSent(self.0)
    }
}

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
pub struct StandingEnded(pub(crate) Option<NodeId>);

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
    pub(crate) fn of(machine: &PeerMachine) -> Self {
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
