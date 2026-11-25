//! One admitted stream to a peer's service, from whichever path this run reaches peers by: its own bind,
//! over the run's [`Peers`], or a running resident, over this home's control socket.
//!
//! A verb asks a [`StreamSource`] for each stream it needs and gets back the two halves the peer
//! admitted, or why it got none, kept typed ([`Unopened`]) so each path prints its own line for it. A
//! stream presents the same thing on both paths ([`presents`]): the link typed as the peer, nothing on a
//! proven-only route, else this home's standing as it reads at that open. An `anyone` run's own bind
//! presents the link alone and reads nothing of the home.

use core::cell::{Cell, RefCell};
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};
use std::collections::HashMap;
use std::rc::Rc;

use bifrost::{ConnInfo, Discovery, NodeId, Session, Transport, WriteEnd};
use nauthy::{Link, Service};
use tokio::io::{self, AsyncRead, AsyncWrite};

use crate::credential::Credential;
use crate::home::Home;
use crate::node_client::{self, Connected, UidSocket};
use crate::observation::{Follow, Observer, Receipt};
use crate::peers::{
    Half, Held, Hints, Isolated, Lane, OPEN_TIMEOUT, OpenError, Peers, Presents, SessionPath,
    Unpresentable, presents,
};
use crate::serve::control_codec::{
    ControlError, MalformedOpen, Observation, OpenLane, OpenRead, OpenRefusal, OpenRequest,
    OpenWrite, PathRef, PeerRefusal,
};

/// One stream asked for: the peer, where to try it first, the service, the lane, and the link typed as
/// the peer, if one was.
///
/// It carries no bytes for the service: nothing rides with or ahead of the open, on either path, and a
/// request is written only on the stream an open returns. So an open that fails delivered no request,
/// which is what lets `stop` say nothing was stopped on every failed open. Keep it so: a field here that
/// sent bytes early would make that line a lie.
///
/// No `Debug`: the slip is a credential, and no log line needs it.
pub struct Ask {
    /// The machine to reach.
    pub peer: NodeId,
    /// Addresses a dial this stream starts tries first. Built by the caller, which reports a list that
    /// is not one open's hints where it was typed.
    pub hints: Hints,
    /// The service to open.
    pub service: Service,
    /// The lane the stream rides.
    pub lane: OpenLane,
    /// The link typed as the peer, presented in place of this home's standing. Cloned for each open,
    /// never taken: a peer that admits only the link refuses a stream without it.
    pub slip: Option<Link>,
}

/// One admitted stream: the path its connection rode as it attached, and its two halves.
pub struct Opened<W, R> {
    /// The connection's path report, read as the stream attached.
    pub info: ConnInfo,
    /// The bytes toward the peer; `shutdown` is the upload's clean end.
    pub write: W,
    /// The peer's bytes.
    pub read: R,
}

/// Why [`StreamSource::open`] gave no stream, kept typed so each path prints its own line for it. It
/// carries no text of its own.
#[derive(Debug)]
pub enum Unopened {
    /// The peer's typed refusal, on both paths, or the resident's own (`Busy`, `StandingEnded`,
    /// `NotHere`, `Unreachable`, `Timeout`, `Broken`, `PeerUnreadable`).
    Refused(OpenRefusal),
    /// By own bind: the open failed on this run's lane cap, its deadline, the dial, or a broken stream.
    /// A peer's refusal never lands here: it is [`Refused`](Self::Refused).
    Own(OpenError),
    /// By own bind: this home or its badge could not be read to present.
    Home(eyre::Report),
    /// Through the resident: its bounded Error reply.
    ServeError(String),
    /// Through the resident: none answers (the connect refused and `serve.lock` is free), one of
    /// another version answers after this run's first open attached, so the run's is gone, or the
    /// control connection was cut before its reply and none answers now.
    ServeGone,
    /// Through the resident: the run's first open met one of another version.
    Skew,
    /// Through the resident: the ask cannot be put as an Open (its slip addresses another machine), so
    /// no request was sent.
    Malformed(MalformedOpen),
    /// Through the resident: the control connection failed before its reply.
    Control(ControlError),
}

impl Unopened {
    /// Whether every later open of this run would repeat this, so the run ends here, a listener's run
    /// included. The peer's `NotAdmitted` is a ruling on this machine the wire says not to
    /// retry, an ended standing's remedy is the person's, the peer being this machine and a malformed
    /// Open both belong to the fixed ask, with no resident there is none to ask, and a control socket
    /// that cannot be trusted fails the same check at every later connect. Anything else belongs to
    /// that one stream. A verb with a fixed set of streams may end on more.
    pub fn ends_run(&self) -> bool {
        match self {
            Self::Refused(
                OpenRefusal::Peer(PeerRefusal::NotAdmitted)
                | OpenRefusal::StandingEnded
                | OpenRefusal::NotHere,
            )
            | Self::ServeGone
            | Self::Skew
            | Self::Malformed(_) => true,
            // One predicate on the error decides, so no list here can miss a variant added later.
            Self::Control(error) => error.distrusts_socket(),
            Self::Refused(
                OpenRefusal::Peer(PeerRefusal::BadRequest(_) | PeerRefusal::Unavailable(_))
                | OpenRefusal::PeerUnreadable(_)
                | OpenRefusal::Unreachable(_)
                | OpenRefusal::Timeout
                | OpenRefusal::Broken(_)
                | OpenRefusal::Busy,
            )
            | Self::Own(_)
            | Self::Home(_)
            | Self::ServeError(_) => false,
        }
    }

    /// Whether the machine was not reached, on either path: the dial failed or a deadline ran out. The
    /// own bind's `Timeout` is the open's deadline on a connected session, the event the resident reports
    /// as its `Timeout`; a dial's deadline is `Unreachable` on both paths.
    pub fn unreached(&self) -> bool {
        matches!(
            self,
            Self::Own(OpenError::Unreachable(_) | OpenError::Timeout)
                | Self::Refused(OpenRefusal::Unreachable(_) | OpenRefusal::Timeout)
        )
    }
}

impl From<OpenError> for Unopened {
    /// The peer's refusal as the typed refusal both paths share; any other failure as the own bind's.
    fn from(error: OpenError) -> Self {
        match error {
            OpenError::Open(bifrost::Error::Refused(refusal)) => {
                Self::Refused(OpenRefusal::from(refusal))
            }
            other => Self::Own(other),
        }
    }
}

/// Where a verb's streams come from: one admitted stream per [`open`](Self::open).
///
/// Written as a returned `impl Future`, not `async fn`, so the trait states no auto-trait bound it does
/// not need; the impls stay plain `async fn`.
pub trait StreamSource {
    /// The bytes toward the peer.
    type Write: AsyncWrite + WriteEnd + Unpin;
    /// The peer's bytes.
    type Read: AsyncRead + Unpin;

    /// One admitted stream to `ask.peer`'s `ask.service` on `ask.lane`, presenting what [`presents`]
    /// says for it, or, by an `anyone` run's own bind, the link alone.
    fn open(
        &self,
        ask: &Ask,
    ) -> impl Future<Output = Result<Opened<Self::Write, Self::Read>, Unopened>>;

    /// Whether the source itself went away, asked once after a stream it opened to `peer` was cut: a
    /// source that keeps a record notes `peer` as where it went. A source that cannot go away says no.
    fn gone(&self, peer: NodeId) -> impl Future<Output = bool> {
        let _ = peer;
        core::future::ready(false)
    }
    /// Whether the source is there and stalled, asked once at a run's end when an open went unanswered.
    /// A source that cannot stall says no.
    fn stalled(&self) -> impl Future<Output = bool> {
        core::future::ready(false)
    }
}

// A borrowed source opens as the source does, so a caller that hands one out by copy can lend it.
impl<S: StreamSource> StreamSource for &S {
    type Write = S::Write;
    type Read = S::Read;

    fn open(
        &self,
        ask: &Ask,
    ) -> impl Future<Output = Result<Opened<Self::Write, Self::Read>, Unopened>> {
        S::open(self, ask)
    }

    fn gone(&self, peer: NodeId) -> impl Future<Output = bool> {
        S::gone(self, peer)
    }
    fn stalled(&self) -> impl Future<Output = bool> {
        S::stalled(self)
    }
}

/// A source that also follows the path of the connection each stream rides, for a verb that prints it.
pub trait Observing: StreamSource {
    /// The one stream, as a session a verb written over a session runs on.
    type Session: Session;
    /// What follows the path of the connection the stream rides.
    type Follow: Follow;

    /// One admitted stream as [`open`](StreamSource::open) gives it, and what follows its connection's
    /// path from the attach on.
    fn observed(
        &self,
        ask: &Ask,
    ) -> impl Future<Output = Result<(Self::Session, Self::Follow), Unopened>>;
}

impl<S: Observing> Observing for &S {
    type Session = S::Session;
    type Follow = S::Follow;

    fn observed(
        &self,
        ask: &Ask,
    ) -> impl Future<Output = Result<(Self::Session, Self::Follow), Unopened>> {
        S::observed(self, ask)
    }
}

/// One admitted stream as a session that hands it out once: what a verb written over a session runs
/// on, on both paths.
///
/// [`peer`](Session::peer) is the key the stream was asked for. By own bind the transport proves it.
/// Through the resident it is claimed by the process answering the socket, which is checked to run as
/// this user and to be the pid `serve.lock` records; neither check holds against a process running as
/// this user, which can bind the path and rewrite `serve.lock`. `H` holds what the stream's place and
/// connection need held, so it stays taken while the session lives. The connection belongs elsewhere,
/// so `wait_closed` never resolves and `close` ends nothing. `accept_bi` refuses, and so does a second
/// `open_bi`: there is one stream.
pub struct OneStream<W, R, H = ()> {
    peer: NodeId,
    info: ConnInfo,
    stream: RefCell<Option<(W, R)>>,
    _held: H,
}

impl<W, R, H> OneStream<W, R, H> {
    /// The stream `opened` to `peer`, holding `held` for as long as the session lives.
    pub fn new(peer: NodeId, opened: Opened<W, R>, held: H) -> Self {
        let Opened { info, write, read } = opened;
        Self {
            peer,
            info,
            stream: RefCell::new(Some((write, read))),
            _held: held,
        }
    }
}

impl<W, R, H> Session for OneStream<W, R, H>
where
    W: AsyncWrite + WriteEnd + Unpin + Send,
    R: AsyncRead + Unpin + Send,
{
    type Write = W;
    type Read = R;

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

    /// The path as the stream attached. A verb that reports its path reads it from what follows the
    /// connection ([`Observing::observed`]).
    fn conn_info(&self) -> ConnInfo {
        self.info.clone()
    }

    /// The path as the stream attached, as a path that never moves.
    fn path_changes(&self) -> bifrost::PathChanges {
        bifrost::PathChanges::fixed(self.info.path.clone())
    }
}

/// The source went away mid-run, at the stream to `peer`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gone {
    /// The machine whose stream met it.
    pub peer: NodeId,
    /// What it met.
    pub why: GoneWhy,
}

/// How a source went away.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GoneWhy {
    /// No resident answers any more.
    Stopped,
    /// A resident of another version answers.
    Skew,
    /// The resident is there and gave no reply in time, to an open nor to a status asked after.
    Unresponsive,
}

impl GoneWhy {
    /// What an open that met `unopened` says of the source itself, if anything: an outcome every later
    /// open through it would meet too.
    fn of(unopened: &Unopened) -> Option<Self> {
        match unopened {
            Unopened::ServeGone => Some(Self::Stopped),
            Unopened::Skew => Some(Self::Skew),
            _ => None,
        }
    }

    /// The outcome every later open meets once the source went so, with no stream asked for.
    fn unopened(self) -> Unopened {
        match self {
            Self::Stopped => Unopened::ServeGone,
            Self::Skew => Unopened::Skew,
            Self::Unresponsive => Unopened::Control(ControlError::Timeout {
                phase: "response read",
            }),
        }
    }
}

/// One run's view of a source that can go away: each ask carries the addresses typed for its peer, and
/// the first sign that the source itself went away is kept, so every later ask returns at once with no
/// stream asked for, and the run's last line can say where it went.
pub struct Tracked<S> {
    source: S,
    /// The addresses typed for each machine, by its key.
    hints: HashMap<NodeId, Hints>,
    // `Cell`s: opens run through `&self` on one task; the first of each is kept.
    gone: Cell<Option<Gone>>,
    /// The first open that got no reply: its caller gave up first, or the reply wait timed out. Only a
    /// candidate: a source dialing a slow machine answers late too, so [`settle`](Self::settle) asks.
    unanswered: Cell<Option<NodeId>>,
}

/// Notes an open still waiting on its reply when its caller drops it.
struct Waiting<'a> {
    unanswered: &'a Cell<Option<NodeId>>,
    peer: Option<NodeId>,
}

impl Waiting<'_> {
    fn answered(mut self) {
        self.peer = None;
    }
}

impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        if let Some(peer) = self.peer
            && self.unanswered.get().is_none()
        {
            self.unanswered.set(Some(peer));
        }
    }
}

impl<S: StreamSource> Tracked<S> {
    /// The streams `source` opens, each to a machine in `hints` carrying that machine's addresses.
    pub fn new(source: S, hints: HashMap<NodeId, Hints>) -> Self {
        Self {
            source,
            hints,
            gone: Cell::new(None),
            unanswered: Cell::new(None),
        }
    }

    /// At the run's end: when an open went unanswered and nothing else said the source went away, ask it
    /// once whether it stalled, and keep that.
    pub async fn settle(&self) {
        if self.gone.get().is_some() {
            return;
        }
        let Some(peer) = self.unanswered.get() else {
            return;
        };
        if self.source.stalled().await {
            self.record(Gone {
                peer,
                why: GoneWhy::Unresponsive,
            });
        }
    }

    /// Where the source went away, and how: the first such outcome of the run.
    pub fn went(&self) -> Option<Gone> {
        self.gone.get()
    }

    fn record(&self, gone: Gone) {
        if self.gone.get().is_none() {
            self.gone.set(Some(gone));
        }
    }
}

impl<S: StreamSource> Tracked<S> {
    /// Start an open of `ask`: the outcome every later open meets once the source went away, else the
    /// note that it waits on its reply, and the ask with the addresses typed for its machine when it
    /// carries none of its own.
    fn start(&self, ask: &Ask) -> Result<(Waiting<'_>, Option<Ask>), Unopened> {
        if let Some(gone) = self.gone.get() {
            return Err(gone.why.unopened());
        }
        let waiting = Waiting {
            unanswered: &self.unanswered,
            peer: Some(ask.peer),
        };
        let hinted = match self.hints.get(&ask.peer) {
            Some(hints) if ask.hints.as_slice().is_empty() => Some(Ask {
                peer: ask.peer,
                hints: hints.clone(),
                service: Service::clone(&ask.service),
                lane: ask.lane,
                slip: Option::clone(&ask.slip),
            }),
            _ => None,
        };
        Ok((waiting, hinted))
    }

    /// An open to `peer` came back: answered unless its reply wait timed out, and the source's going
    /// kept when `unopened` says it went.
    fn heard(&self, waiting: Waiting<'_>, peer: NodeId, unopened: Option<&Unopened>) {
        match unopened {
            Some(Unopened::Control(ControlError::Timeout { .. })) => {}
            _ => waiting.answered(),
        }
        if let Some(why) = unopened.and_then(GoneWhy::of) {
            self.record(Gone { peer, why });
        }
    }
}

impl<S: StreamSource> StreamSource for Tracked<S> {
    type Write = S::Write;
    type Read = S::Read;

    async fn open(&self, ask: &Ask) -> Result<Opened<Self::Write, Self::Read>, Unopened> {
        let (waiting, hinted) = self.start(ask)?;
        let opened = self.source.open(hinted.as_ref().unwrap_or(ask)).await;
        self.heard(waiting, ask.peer, opened.as_ref().err());
        opened
    }

    async fn stalled(&self) -> bool {
        self.source.stalled().await
    }

    async fn gone(&self, peer: NodeId) -> bool {
        let gone = self.source.gone(peer).await;
        if gone {
            self.record(Gone {
                peer,
                why: GoneWhy::Stopped,
            });
        }
        gone
    }
}

// Filled and recorded as its `open` is.
impl<S: Observing> Observing for Tracked<S> {
    type Session = S::Session;
    type Follow = S::Follow;

    async fn observed(&self, ask: &Ask) -> Result<(Self::Session, Self::Follow), Unopened> {
        let (waiting, hinted) = self.start(ask)?;
        let observed = self.source.observed(hinted.as_ref().unwrap_or(ask)).await;
        self.heard(waiting, ask.peer, observed.as_ref().err());
        observed
    }
}

/// The streams of a run that bound its own endpoint: each rides the run's [`Peers`], presenting what
/// [`presents`] reads from `home` for the machine `this`, or, for an `anyone` run, the link alone.
pub struct OwnBind<'p, 'n, T: Transport, D: Discovery> {
    peers: &'p Peers<'n, T, D>,
    home: &'p Home,
    this: NodeId,
    presenting: Presenting,
}

/// What each open of an own bind presents, fixed by the run's [`Credential`]: the same value that chose
/// the key the run bound, so the bind and what rides it cannot disagree.
#[derive(Clone, Copy)]
enum Presenting {
    /// This home's standing, or the slip with this home's badge beside it, as [`presents`] reads them.
    Home,
    /// The link typed as the peer alone, under a throwaway key: no read of this home, so nothing of it
    /// travels with the link, and a home that cannot be read stops nothing.
    Alone,
}

impl<'p, 'n, T: Transport, D: Discovery> OwnBind<'p, 'n, T, D> {
    /// The streams `peers` opens for the run bound as `this` with `credential`, presenting from `home`
    /// unless the credential presents alone.
    pub fn new(
        peers: &'p Peers<'n, T, D>,
        home: &'p Home,
        this: NodeId,
        credential: &Credential,
    ) -> Self {
        let presenting = match credential {
            Credential::Family { .. } => Presenting::Home,
            Credential::Anyone(_) => Presenting::Alone,
        };
        Self {
            peers,
            home,
            this,
            presenting,
        }
    }

    /// What `ask` presents on this bind: an `anyone` run's slip alone, read from nothing, else what
    /// [`presents`] reads from the home now.
    async fn presents(&self, ask: &Ask) -> Result<Presents, Unopened> {
        let slip = Option::clone(&ask.slip);
        match self.presenting {
            Presenting::Alone => Ok(match slip {
                Some(slip) => Presents::Slip {
                    slip,
                    membership: None,
                },
                None => Presents::Standing(None),
            }),
            Presenting::Home => presents(self.home, self.this, &ask.service, slip)
                .await
                .map_err(|unpresentable| match unpresentable {
                    Unpresentable::Ended => Unopened::Refused(OpenRefusal::StandingEnded),
                    Unpresentable::Unreadable(report) => Unopened::Home(report),
                }),
        }
    }

    /// One stream on a connection of its own, which the stream's halves hold between them: it closes
    /// once both, and any other holder of the connection, have dropped.
    async fn isolated(
        &self,
        ask: &Ask,
        presents: Presents,
    ) -> Result<
        (
            Opened<<Self as StreamSource>::Write, <Self as StreamSource>::Read>,
            Rc<Isolated<T::Session>>,
        ),
        Unopened,
    > {
        let connection = Rc::new(self.peers.isolated(ask.peer, ask.hints.clone()).await?);
        let connector = presents.connector(ask.peer, Service::clone(&ask.service));
        // Bulk's deadline: nothing is evicted and nothing races this open.
        let (write, read) =
            match tokio::time::timeout(OPEN_TIMEOUT, connector.open_on(&*connection)).await {
                Ok(Ok(halves)) => halves,
                Ok(Err(error)) => return Err(OpenError::Open(error).into()),
                Err(_elapsed) => return Err(Unopened::Own(OpenError::Timeout)),
            };
        let info = connection.conn_info();
        let (write, read) = Rc::clone(&connection).lend(write, read);
        Ok((Opened { info, write, read }, connection))
    }

    /// The lane `ask` rides, or `None` for a connection of its own.
    fn lane(ask: &Ask) -> Option<Lane> {
        match ask.lane {
            OpenLane::Main => Some(Lane::Main),
            OpenLane::Bulk => Some(Lane::Bulk),
            OpenLane::Isolated => None,
        }
    }
}

// By hand: the endpoint's types need not be `Clone` for a borrow of them to be.
impl<T: Transport, D: Discovery> Clone for OwnBind<'_, '_, T, D> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T: Transport, D: Discovery> Copy for OwnBind<'_, '_, T, D> {}

impl<T: Transport, D: Discovery> StreamSource for OwnBind<'_, '_, T, D> {
    type Write = Half<<T::Session as Session>::Write, T::Session>;
    type Read = Half<<T::Session as Session>::Read, T::Session>;

    async fn open(&self, ask: &Ask) -> Result<Opened<Self::Write, Self::Read>, Unopened> {
        let presents = self.presents(ask).await?;
        let Some(lane) = Self::lane(ask) else {
            return Ok(self.isolated(ask, presents).await?.0);
        };
        let (info, _end, write, read) = self
            .peers
            .open_attached(
                ask.peer,
                ask.hints.clone(),
                Service::clone(&ask.service),
                lane,
                presents,
            )
            .await?;
        Ok(Opened { info, write, read })
    }
}

// The transport's own halves, split from the lease the session keeps: `measure` drops both at the end of
// its run, when the session drops too, so the place is held for as long either way.
impl<T: Transport, D: Discovery> Observing for OwnBind<'_, '_, T, D> {
    type Session =
        OneStream<<T::Session as Session>::Write, <T::Session as Session>::Read, Held<T::Session>>;
    type Follow = SessionPath<T::Session>;

    async fn observed(&self, ask: &Ask) -> Result<(Self::Session, Self::Follow), Unopened> {
        let presents = self.presents(ask).await?;
        let (opened, follow) = match Self::lane(ask) {
            Some(lane) => {
                let (info, end, write, read) = self
                    .peers
                    .open_attached(
                        ask.peer,
                        ask.hints.clone(),
                        Service::clone(&ask.service),
                        lane,
                        presents,
                    )
                    .await?;
                (Opened { info, write, read }, SessionPath::Held(end))
            }
            None => {
                let (opened, connection) = self.isolated(ask, presents).await?;
                (opened, SessionPath::Isolated(connection))
            }
        };
        let Opened { info, write, read } = opened;
        let (write, held) = write.split();
        let (read, _same) = read.split();
        Ok((
            OneStream::new(ask.peer, Opened { info, write, read }, held),
            follow,
        ))
    }
}

/// The streams of a run through the resident at this home's control socket: each is one Open there, on
/// a control connection of its own, since an Open spends the connection it rides.
pub struct Resident {
    socket: Rc<UidSocket>,
    /// Whether an Open of this run has attached, so a resident of another version answering now is a
    /// restarted one and the run's is gone.
    // A `Cell`: opens run through `&self` on one task.
    attached: Cell<bool>,
}

impl Resident {
    /// The streams the resident at `socket` opens.
    pub fn new(socket: Rc<UidSocket>) -> Self {
        Self {
            socket,
            attached: Cell::new(false),
        }
    }

    /// Send `ask` as an Open on `connected`, asking for a reference to its connection when `observation`
    /// says so: the stream with its write half as the socket gives it, and the reference.
    ///
    /// # Errors
    ///
    /// The resident's or the peer's refusal, its Error reply, another version answering ([`Skew`]), or
    /// the control connection failing before its reply.
    ///
    /// [`Skew`]: Unopened::Skew
    pub async fn attach(
        connected: Connected,
        ask: &Ask,
        observation: Observation,
    ) -> Result<(Opened<OpenWrite, OpenRead>, Option<PathRef>), Unopened> {
        let request = OpenRequest::new(
            ask.peer,
            ask.hints.clone(),
            Service::clone(&ask.service),
            ask.lane,
            Option::clone(&ask.slip),
        )
        .map_err(Unopened::Malformed)?;
        let request = match observation {
            Observation::Unobserved => request,
            Observation::Observed => request.observed(),
        };
        match connected.open(request).await {
            Ok(node_client::Opened::Attached {
                info,
                reference,
                read,
                write,
            }) => Ok((Opened { info, write, read }, reference)),
            Ok(node_client::Opened::Refused(refusal)) => Err(Unopened::Refused(refusal)),
            Ok(node_client::Opened::Error(reason)) => Err(Unopened::ServeError(reason)),
            Err(ControlError::Version { .. }) => Err(Unopened::Skew),
            Err(error) => Err(Unopened::Control(error)),
        }
    }

    /// Send `ask` as an observed Open on `connected`: the stream, and the observer that follows its
    /// connection through this socket, read from the Attached report on.
    async fn attach_observed(
        &self,
        connected: Connected,
        ask: &Ask,
    ) -> Result<(Opened<OpenWrite, OpenRead>, Observer), Unopened> {
        let (opened, reference) = Self::attach(connected, ask, Observation::Observed).await?;
        // The client hands out no halves on an Attached whose reference does not match the Open.
        let Some(reference) = reference else {
            return Err(Unopened::Control(ControlError::Protocol(
                "attached lacks the requested path reference".to_owned(),
            )));
        };
        let observer = Observer::new(
            Receipt::new(reference, Rc::clone(&self.socket)),
            opened.info.clone(),
        );
        self.attached.set(true);
        Ok((opened, observer))
    }
}

impl Resident {
    /// A control connection of its own for one Open: a refused connect with `serve.lock` free is the
    /// resident gone.
    async fn connect(&self) -> Result<Connected, Unopened> {
        match self.socket.connected().await {
            Ok(connected) => Ok(connected),
            Err(ControlError::NoResident) if self.socket.lock_free().await => {
                Err(Unopened::ServeGone)
            }
            Err(error) => Err(Unopened::Control(error)),
        }
    }

    /// What an Open that attached nothing means for the run: another version answering after one of
    /// its Opens attached is a restarted resident, and a cut before the reply with none answering now
    /// is the resident gone.
    async fn settled(&self, unopened: Unopened) -> Unopened {
        match unopened {
            Unopened::Skew if self.attached.get() => Unopened::ServeGone,
            Unopened::Control(error) if self.socket.gone().await => {
                // Debug, not Display: a Timeout's text names no phase, and the log should.
                tracing::debug!(
                    ?error,
                    "an open through serve was cut before its reply, and serve is gone"
                );
                Unopened::ServeGone
            }
            unopened => unopened,
        }
    }
}

impl StreamSource for Resident {
    type Write = Upload;
    type Read = OpenRead;

    async fn open(&self, ask: &Ask) -> Result<Opened<Self::Write, Self::Read>, Unopened> {
        let connected = self.connect().await?;
        match Self::attach(connected, ask, Observation::Unobserved).await {
            Ok((Opened { info, write, read }, _unobserved)) => {
                self.attached.set(true);
                Ok(Opened {
                    info,
                    write: Upload::from(write),
                    read,
                })
            }
            Err(unopened) => Err(self.settled(unopened).await),
        }
    }

    /// Asked of the socket, bounded: no status answers and `serve.lock` is free.
    async fn gone(&self, _peer: NodeId) -> bool {
        self.socket.gone().await
    }

    /// Asked of the socket, bounded: a status gets no reply in time while `serve.lock` is held.
    async fn stalled(&self) -> bool {
        self.socket.stalled().await
    }
}

impl Observing for Resident {
    type Session = OneStream<Upload, OpenRead>;
    type Follow = Observer;

    /// An observed Open on a control connection of its own, connected and mapped as
    /// [`open`](StreamSource::open)'s is.
    async fn observed(&self, ask: &Ask) -> Result<(Self::Session, Self::Follow), Unopened> {
        let connected = self.connect().await?;
        match self.attach_observed(connected, ask).await {
            Ok((Opened { info, write, read }, observer)) => {
                let opened = Opened {
                    info,
                    write: Upload::from(write),
                    read,
                };
                Ok((OneStream::new(ask.peer, opened, ()), observer))
            }
            Err(unopened) => Err(self.settled(unopened).await),
        }
    }
}

/// The write half of a stream through the resident, as a transport's: Data frames, and End at its
/// `shutdown`. Aborted, or dropped before `shutdown`, it closes the direction with no End, which the
/// resident passes on to the peer as a reset. Its `delivered` never resolves: the word that the peer
/// holds the upload is the read half's.
pub struct Upload(Option<OpenWrite>);

impl From<OpenWrite> for Upload {
    fn from(write: OpenWrite) -> Self {
        Self(Some(write))
    }
}

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

    /// Never resolves: through the resident the word that the peer holds the upload is Landed, which
    /// arrives on the read half ([`OpenRead::landed`]), out of this half's reach. Pending forever is the
    /// answer the transport contract gives for a peer that never takes the bytes, so a caller's own bound
    /// ends the wait; any error here would claim a reset, a stopped reader or a lost session that did not
    /// happen. It writes no End, and it holds the half until the wait is dropped, so the direction ends
    /// as the caller left it: cleanly after its `shutdown`, else as a cut once the caller gives up.
    async fn delivered(self) -> io::Result<()> {
        let _held = self;
        core::future::pending().await
    }
}

#[cfg(test)]
#[path = "streams_tests.rs"]
mod tests;
