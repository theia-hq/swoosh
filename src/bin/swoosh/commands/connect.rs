//! The one swoosh connect runner, and the [`To`] sink selector it is parameterized by.
//!
//! NOT a verb: `swoosh forward <peer> <service> <port | unix:<path> | ->` is the surface, and this is
//! the body it drives. The two halves are split because the act ("dial a peer's served service,
//! optionally presenting a cap, then drive it") is one thing while WHERE the bytes go is a choice the
//! caller makes: `Port` binds a local port and forwards each connection, `Stdout` streams the single
//! stream over this process's stdin/stdout, `UnixListener` is reserved. The present/badge
//! choice lives in exactly one place (the caller picks `present` before handing off).
//!
//! `swoosh ssh` reaches the same runner the same way, through the PUBLIC verb: its `ProxyCommand`
//! re-invokes THIS binary as `<self> forward <peer> <service> -` via `current_exe()` (not a separate
//! `tightbeam` binary on PATH), so the bridge an operator debugs by hand is the one ssh runs.
//!
//! The own bind ends when the host cuts the session (on a revoke or an expiry), whatever the local
//! side is doing. Through `serve` the stdout sink ends the same way: [`pump_stdio`] says how, including
//! that a stdin that is not a terminal still finishes its upload after a clean end. A port through
//! `serve` holds no session to watch, so it ends when a pipe finds the run over (`through_serve` names
//! the outcomes that do); by own bind a pipe's `NotAdmitted` ends it too, the one refusal every later
//! pipe would meet. Any other pipe's failure keeps the port listening. tightbeam's own stdio bridge and
//! port forward end neither way yet: the bridge
//! waits on a stdin read before the process can exit, and the forward keeps listening on a session
//! that is gone. So the exchange, the bridge and the forward live here, over tightbeam's wire
//! frames, until tightbeam's own end the same way.

use core::future::Future;
use core::ops::ControlFlow;
use core::pin::Pin;
use core::str::FromStr;
use core::task::{Context, Poll};
use core::time::Duration;
use std::io::{IsTerminal as _, Read as _};
use std::path::PathBuf;

use bifrost::{Discovery, Node, NodeId, Refusal, Session, Transport};
use futures::StreamExt as _;
use futures::stream::FuturesUnordered;
use nauthy::{Link, Service};
use swoosh::contacts::Contacts;
use swoosh::escape::escaped_report;
use swoosh::peer::Machine as PeerMachine;
use swoosh::peers::{Hints, Lane, OpenError, Peers, Presents, SessionEnd};
use tightbeam::protocol::{Request, Response};
use tightbeam::tunnel::DialRefused;
use tokio::io::{self, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use crate::commands::machine;

/// Where a reached service's bytes go locally: `forward`'s local end, parsed to a closed enum so the
/// three sinks are disjoint and "two sinks at once" is unrepresentable (no `ArgGroup`, no two-bool trap).
///
/// swoosh's OWN selector, so its connect surfaces never name tightbeam's CLI-layer arg type. The arms are
/// distinguished by a prefix test BEFORE any numeric parse, so `unix:` can never collide with a port, `-`
/// can never collide with a path, and a bare path can never masquerade as either:
///
/// - `unix:<path>` -> [`To::UnixListener`] (everything after the prefix is the path, verbatim); reserved.
/// - `-` -> [`To::Stdout`] (the universal Unix idiom: stream the single service to this process's stdout).
/// - a `u16` in `1..=65535` -> [`To::Port`] (bind `127.0.0.1:<port>`, a local TCP listener).
///
/// Anything else (a bare path, `fifo:`, `file:`, `0`, `70000`) is a hard parse error naming the three
/// legal forms, so a bare path is never a silent anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum To {
    /// Bind `127.0.0.1:<port>` and forward each accepted connection to the peer's service (`ssh -L` shaped).
    Port(u16),
    /// Stream the single service to this process's stdout (composes with the shell: `> file`, `| mpv -`).
    Stdout,
    /// Bind a local `AF_UNIX` listener at `<path>` (the unix-domain analog of a port). RESERVED: parsing
    /// recognizes it so a `unix:` target is never a silent misparse, but the listener is not yet built.
    UnixListener(PathBuf),
}

impl FromStr for To {
    type Err = eyre::Error;

    fn from_str(text: &str) -> eyre::Result<Self> {
        // Prefix-test `unix:` first, then `-`, then a port: the arms are disjoint by their first token, so
        // there is never a "which did you mean" case (see the type docs).
        if let Some(path) = text.strip_prefix("unix:") {
            return Ok(To::UnixListener(PathBuf::from(path)));
        }
        if text == "-" {
            return Ok(To::Stdout);
        }
        match text.parse::<u16>() {
            Ok(port) if port != 0 => Ok(To::Port(port)),
            _ => eyre::bail!("a local end is a port (5432), unix:<path>, or - for stdout"),
        }
    }
}

/// The ONE connect path, driven by `forward` directly and by `swoosh ssh` through it. Dial the resolved
/// `machine` presenting slot 1 (the grant) and slot 2 (a membership badge for a signet-bound slip's AND),
/// then drive the sink [`To`] names: forward a local port (proving admission, then printing swoosh's own
/// start lines on stderr), stream stdin/stdout (no banner: ssh owns the tty), or the reserved unix
/// listener. A refused forward surfaces the refusal here and exits non-zero, never a fake banner.
///
/// A port's streams ride the machine's held Bulk session in the run's `peers`, presenting `presents`,
/// the same two slots as the owner keys them.
#[expect(
    clippy::too_many_arguments,
    reason = "the uniform reach context, unpacked"
)]
pub async fn connect<'n, T: Transport, D: Discovery>(
    node: &'n Node<T, D>,
    peers: &Peers<'n, T, D>,
    contacts: &Contacts,
    machine: &PeerMachine,
    service: Service,
    slot1: Option<Link>,
    slot2: Option<Link>,
    presents: Presents,
    to: To,
) -> eyre::Result<()> {
    let refused = Refused {
        machine,
        service: &service,
        slot1: &slot1,
        slot2: &slot2,
    };
    match to {
        To::Port(port) => {
            let pipes = OwnPipes {
                node,
                peers,
                refused: &refused,
                presents,
            };
            pipes
                .forward_port(&Machine::of(contacts, machine.key()), port)
                .await
                .map_err(escaped)
        }
        To::Stdout => {
            // The opening frame the stream sends.
            let request = Request {
                service: service.to_string(),
                capability: slot1.as_ref().map(ToString::to_string),
                membership: slot2.as_ref().map(ToString::to_string),
            };
            pipe_stdio(node, &refused, &request).await.map_err(escaped)
        }
        // The path is not echoed: a typed path would read as a missing socket, not a missing feature.
        To::UnixListener(_) => {
            eyre::bail!("a unix:<path> local end is not built yet: use a port, or - for stdout")
        }
    }
}

/// Open one stream on `session` and ask the host for the service: the admitted halves, or the host's
/// refusal.
///
/// Every failure comes back as its own error, unwrapped, so a printed line names what failed (`early eof`)
/// and reads the same on both sinks.
async fn admitted<S: Session>(
    session: &S,
    request: &Request,
) -> eyre::Result<Result<(S::Write, S::Read), Refusal>> {
    let (mut writer, mut reader) = session.open_bi().await?;
    request.write(&mut writer).await?;
    Ok(match Response::read(&mut reader).await? {
        Response::Ok => Ok((writer, reader)),
        Response::Refused(refusal) => Err(refusal),
    })
}

/// `error` with any peer text in its chain escaped, except the dial refusal, which carries none and whose
/// line breaks are its own.
fn escaped(error: eyre::Report) -> eyre::Report {
    if error.is::<machine::Refused>() {
        error
    } else {
        escaped_report(error)
    }
}

/// What a dial needs to say why it was refused: the machine, the service asked for, and the slots the
/// refused dial presented, which the follow-up to one of your devices presents again.
struct Refused<'a> {
    machine: &'a PeerMachine,
    service: &'a Service,
    slot1: &'a Option<Link>,
    slot2: &'a Option<Link>,
}

impl Refused<'_> {
    /// The error a refusal on `session` ends the run with: a `NotAdmitted` is the dial refusal, after one
    /// of your devices is asked why on the same session; any other refusal keeps the host's own reason.
    async fn on<S: Session>(&self, session: &S, refusal: Refusal) -> eyre::Report {
        match refusal {
            Refusal::NotAdmitted => {
                let diagnosis = swoosh::reach::diagnose(
                    session,
                    self.machine,
                    self.service,
                    Option::clone(self.slot1),
                    Option::clone(self.slot2),
                )
                .await;
                machine::refused(self.machine, self.service, diagnosis)
            }
            refusal => DialRefused {
                dial: self.machine.key(),
                refusal,
            }
            .into(),
        }
    }

    /// The error a `NotAdmitted` from a held session ends the run with: the dial refusal, after one of
    /// your devices is asked why over a connection of its own on `node`, once per run, after its loop.
    async fn over<T: Transport, D: Discovery>(&self, node: &Node<T, D>) -> eyre::Report {
        let diagnosis = swoosh::reach::diagnose_over(
            node,
            self.machine,
            self.service,
            Option::clone(self.slot1),
            Option::clone(self.slot2),
        )
        .await;
        machine::refused(self.machine, self.service, diagnosis)
    }
}

/// A port's streams by own bind: the admission and every pipe, each one stream on the machine's held
/// Bulk session in the run's [`Peers`], so a forward's fan-out never takes the slots the run's other
/// streams to the machine need.
struct OwnPipes<'a, 'p, 'n, T: Transport, D: Discovery> {
    node: &'n Node<T, D>,
    peers: &'p Peers<'n, T, D>,
    refused: &'a Refused<'a>,
    presents: Presents,
}

impl<T: Transport, D: Discovery> OwnPipes<'_, '_, '_, T, D> {
    /// Prove the gate admits this request, bind the local port, say so on stderr naming `machine`, then
    /// forward each local connection over its own stream until the run ends: the host cuts the session,
    /// or a pipe meets a refusal every later one would.
    ///
    /// Admission is proven on one stream before the line prints, so a refusal fails here with the host's
    /// reason rather than as a silent reset once the line is out. Every later stream presents the same
    /// request to the same gate. stdout stays empty: the port was typed, so the line carries nothing a
    /// script needs, and `forward`'s stdout is only ever the stream.
    async fn forward_port(&self, machine: &Machine, port: u16) -> eyre::Result<()> {
        // The admission stream is dropped once admitted, and the host tears its half down. Its session
        // is the one the run watches until a pipe rides another.
        let end = match self.open().await {
            Ok((end, _, _)) => end,
            Err(error) => return Err(self.failed(error).await),
        };
        let listener = TcpListener::bind(("127.0.0.1", port)).await?;
        forwarding(self.refused.service, machine, port);
        Err(self.forward(listener, end).await)
    }

    /// Forward each accepted local connection over its own stream until the run ends, and return the
    /// line it ends with: [`ConnectionLost`] when the session the latest stream rode closes (the host cut
    /// it on a revoke or an expiry, or the path to it failed), else a pipe's line that ends it.
    ///
    /// The watch follows the latest stream, starting from `first`'s ([`session_cut`]). A pipe's
    /// `NotAdmitted` breaks the loop at once, and one of your devices is asked why only after it, once
    /// per run: never a follow-up dial per refused pipe, and never one the cut can race.
    async fn forward(&self, listener: TcpListener, first: SessionEnd<T::Session>) -> eyre::Report {
        let (rode, latest) = mpsc::unbounded_channel();
        // The receiver is held below, so the send cannot fail.
        let _ = rode.send(first);
        let pipes = accept_each(listener, MAX_PIPES, |tcp| self.carry(tcp, &rode));
        let ended = tokio::select! {
            // The cut first: a pipe that broke with its session is polled only after the run has
            // ended on `connection lost`, so no line of the pipe's carries the cut's reason.
            biased;
            () = session_cut(latest) => ConnectionLost.into(),
            ended = pipes => ended,
        };
        if ended.is::<NotAdmittedLater>() {
            return self.refused.over(self.node).await;
        }
        ended
    }

    /// Carry one local connection over its own admitted stream, both ways, until both sides close, and
    /// tell `rode` which session it rode. A `NotAdmitted` breaks the run with [`NotAdmittedLater`], for
    /// the run to word once; any other failure is this pipe's, for the log.
    async fn carry(
        &self,
        mut tcp: TcpStream,
        rode: &mpsc::UnboundedSender<SessionEnd<T::Session>>,
    ) -> ControlFlow<eyre::Report> {
        let (end, writer, reader) = match self.open().await {
            Ok(opened) => opened,
            Err(error) if ends_the_run(&error) => {
                return ControlFlow::Break(NotAdmittedLater.into());
            }
            // One connection's failure is not the forward's: it goes to the log, not to the person.
            Err(error) => {
                tracing::warn!("connection failed: {error:#}");
                return ControlFlow::Continue(());
            }
        };
        // A failed send means the run is over and nothing watches any more.
        let _ = rode.send(SessionEnd::clone(&end));
        if let Err(error) = io::copy_bidirectional(&mut tcp, &mut io::join(reader, writer)).await {
            tracing::warn!("connection failed: {error:#}");
        }
        ControlFlow::Continue(())
    }

    /// One admitted stream on the machine's held Bulk session, with the watch on that session.
    async fn open(
        &self,
    ) -> Result<
        (
            SessionEnd<T::Session>,
            impl io::AsyncWrite + Unpin,
            impl io::AsyncRead + Unpin,
        ),
        OpenError,
    > {
        let (_, end, writer, reader) = self
            .peers
            .open_attached(
                self.refused.machine.key(),
                Hints::NONE,
                Service::clone(self.refused.service),
                Lane::Bulk,
                Presents::clone(&self.presents),
            )
            .await?;
        Ok((end, writer, reader))
    }

    /// The line the admission prints when its stream did not open: the dial refusal for a `NotAdmitted`,
    /// the host's own reason for any other refusal, and an exchange that failed as its own cause,
    /// unwrapped, as the stdout sink prints it.
    async fn failed(&self, error: OpenError) -> eyre::Report {
        match error {
            OpenError::Open(bifrost::Error::Refused(Refusal::NotAdmitted)) => {
                self.refused.over(self.node).await
            }
            OpenError::Open(bifrost::Error::Refused(refusal)) => DialRefused {
                dial: self.refused.machine.key(),
                refusal,
            }
            .into(),
            OpenError::Open(bifrost::Error::Stream(cause)) => eyre::eyre!(cause),
            other => other.into(),
        }
    }
}

/// Resolve once the session the latest stream rode has closed: the host cut it on a revoke or an expiry,
/// or the path to it failed. Each stream's watch arrives on `rode` as it opens, the first one before
/// anything closes; until one does, and after every sender has gone, this waits.
///
/// A channel, not a shared cell: the watch must wake to re-arm when a stream rides a new session, and a
/// send is what wakes it. The owner can drop an idle session from its map while a watch holds it open,
/// so the run's session is the latest stream's, never only the first's. Unbounded, since each stream
/// sends once and this, on the run's task, drains it as it runs.
pub async fn session_cut<S: Session>(mut rode: mpsc::UnboundedReceiver<SessionEnd<S>>) {
    let Some(mut watched) = rode.recv().await else {
        return core::future::pending().await;
    };
    loop {
        tokio::select! {
            () = watched.closed() => return,
            Some(end) = rode.recv() => watched = end,
        }
    }
}

/// Whether a later pipe's own-bind failure ends the run, by the rule the resident's outcomes are sorted
/// by: only the machine's `NotAdmitted` does, a ruling on this machine (a revoke or a pause) that the wire
/// says not to retry, so listening on would refuse every connection. The resident's other two, an ended
/// standing and this machine as the target, are no own-bind open's outcome: by own bind a lease end cuts
/// the session instead. Every other failure, a refusal this build cannot read among them, is that pipe's.
pub fn ends_the_run(error: &OpenError) -> bool {
    matches!(
        error,
        OpenError::Open(bifrost::Error::Refused(Refusal::NotAdmitted))
    )
}

/// The start lines of a forwarded port, on stderr, once admission is proven: one shape on both paths.
pub fn forwarding(service: &impl core::fmt::Display, machine: &Machine, port: u16) {
    eprintln!("Forwarding {service} on {machine} to 127.0.0.1:{port}.");
    press_ctrl_c();
}

/// The second start line of a long-running local end, on stderr, at a terminal only: a supervisor or a
/// script reading the stream has no ctrl-c to press.
pub fn press_ctrl_c() {
    if std::io::stderr().is_terminal() {
        eprintln!("Press ctrl-c to stop.");
    }
}

/// A machine as a printed line names it: the name this home holds for its key (`me/nas`, `alice/laptop`),
/// else the whole key. Never a short key, which no command accepts, and never a link, whose token prints
/// only as the artifact that made it. Built from the key actually dialed, so a link typed as the peer
/// prints as the machine it addresses.
pub struct Machine(String);

impl Machine {
    /// How `node` prints for a person reading this home's lines.
    pub fn of(contacts: &Contacts, node: NodeId) -> Self {
        Self(match contacts.saved_at(&node) {
            Some(name) => name.to_string(),
            None => node.to_string(),
        })
    }
}

impl core::fmt::Display for Machine {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The most local connections one forward or proxy holds at once, carried or waiting for a stream. Below
/// the streams one iroh session carries (at least 224), and far enough below a default descriptor limit (256 on
/// macOS) that connections waiting for a stream cannot exhaust the process. Past it, new connections wait
/// in the kernel's listen backlog.
pub const MAX_PIPES: usize = 128;

/// How long a local listener waits before accepting again after an accept fails. An error such as running
/// out of descriptors repeats on every attempt until something frees, so retrying at once would spin.
pub const ACCEPT_RETRY: Duration = Duration::from_millis(100);

/// Accept each local connection and hand it to `carry`, all carried concurrently, until one of them
/// breaks the run: its line is what this returns.
///
/// At most `cap` are held at once ([`MAX_PIPES`] in a run; past it, new connections wait in the kernel's
/// backlog), and a failed accept pauses for [`ACCEPT_RETRY`] rather than spinning. One failed accept or
/// pipe never tears down the ones in flight: a pipe logs its own failure and continues the run.
pub async fn accept_each<F, Fut>(listener: TcpListener, cap: usize, mut carry: F) -> eyre::Report
where
    F: FnMut(TcpStream) -> Fut,
    Fut: Future<Output = ControlFlow<eyre::Report>>,
{
    let mut pipes = FuturesUnordered::new();
    // Set after a failed accept: accepting resumes once `retry` fires.
    let retry = tokio::time::sleep(Duration::ZERO);
    tokio::pin!(retry);
    let mut paused = false;
    loop {
        tokio::select! {
            () = &mut retry, if paused => paused = false,
            // Accept only below the cap: a connection waiting for its stream holds a descriptor.
            accepted = listener.accept(), if !paused && pipes.len() < cap => match accepted {
                Ok((tcp, _)) => pipes.push(carry(tcp)),
                Err(error) => {
                    tracing::warn!(%error, "local accept failed; still listening");
                    retry.as_mut().reset(tokio::time::Instant::now() + ACCEPT_RETRY);
                    paused = true;
                }
            },
            Some(flow) = pipes.next(), if !pipes.is_empty() => {
                if let ControlFlow::Break(report) = flow {
                    return report;
                }
            }
        }
    }
}

/// A forward's remote stream ended. No source chain can disclose a transport or cut reason.
#[derive(Debug, thiserror::Error)]
#[error("connection lost")]
pub struct ConnectionLost;

/// A later pipe's `NotAdmitted` by own bind, which ends the run: the loop breaks with this at once, and
/// the run then words it as the dial refusal, asking one of your devices why. Never printed as it is.
#[derive(Debug, thiserror::Error)]
#[error("not admitted")]
pub struct NotAdmittedLater;

/// Reach the service over one stream and pipe it against this process's stdin and stdout: the bridge
/// `swoosh ssh` runs as its `ProxyCommand`.
///
/// When the stream from the host fails or the session closes (the host cut it on a revoke or an
/// expiry), the run is over, whatever stdin is doing; how a clean end ends the run is
/// [`pump_stdio`]'s. stdin is read on its own thread (see [`stdin_chunks`]), so nothing waits on a
/// read that, at a terminal or under ssh, only returns when the person types again.
async fn pipe_stdio<T: Transport, D: Discovery>(
    node: &Node<T, D>,
    refused: &Refused<'_>,
    request: &Request,
) -> eyre::Result<()> {
    // Held for the whole pump: the stream rides this session, which closes when it drops.
    let session = node.connect(refused.machine.key()).await?;
    let (writer, reader) = match admitted(&session, request).await? {
        Ok(halves) => halves,
        Err(Refusal::NotAdmitted) => return Err(refused.on(&session, Refusal::NotAdmitted).await),
        Err(refusal) => return Err(bifrost::Error::Refused(refusal).into()),
    };
    pump_stdio(
        Stream(writer),
        OwnRead {
            half: reader,
            session: &session,
        },
        Stdin::open()?,
        Stdout::default(),
    )
    .await
}

/// Endpoint provenance, not session closure, identifies a failed remote stream: its error can arrive
/// before the session's close signal. Local stdin/stdout failures stay local even after a host cut.
///
/// The upload ends cleanly only at stdin's end; every other way out cuts it, so the far service reads a
/// reset and never a clean end of a truncated upload: a stdin read error, a failed write toward the
/// host, a failed stdout write, a failed download, and a download that ends first on a terminal (a
/// person's session is over when the far side closes, and what was typed has already gone).
///
/// When the download ends first on any other stdin (a file, a pipe, a ProxyCommand's pipe), stdout is
/// closed at once, so whatever reads it sees its end now: a ProxyCommand host can wait for that end before
/// it closes our stdin. The upload then runs to stdin's end. While stdin idles, the connection is
/// watched (the session on the own bind, the resident's connection through `serve`), so one that ends
/// without the word that the upload landed ends the run at once.
///
/// After a clean upload end the run waits for the whole download, then, when the upload carried a byte,
/// for the word that it landed, from whichever half carries it, with no clock: exit 0 says the far side
/// holds every byte. An empty upload has nothing to lose, and a service that stopped reading before its
/// end never says it landed.
pub(crate) async fn pump_stdio(
    mut writer: impl Upload,
    reader: impl Download,
    input: Stdin,
    output: impl Output,
) -> eyre::Result<()> {
    /// What the upload carried before its clean end.
    enum Carried {
        /// stdin ended before a byte was read.
        Nothing,
        /// At least one byte went out.
        Data,
    }
    /// How the upload failed.
    enum UpFailed {
        /// stdin failed.
        Local(io::Error),
        /// A write toward the host failed.
        Remote(io::Error),
    }
    /// How the run settled, once the upload is no longer being written.
    enum Settled<R> {
        /// The run ends with this, and the upload, unfinished, is cut.
        Cut(eyre::Result<()>),
        /// The upload ended cleanly and the download failed: the run ends with this.
        Done(eyre::Report),
        /// The upload ended cleanly and the download is whole: the word that it landed is next.
        Uploaded(Carried, R),
    }
    impl UpFailed {
        /// The failure as the run's end: a local one as it is, a remote one as the cut-off.
        fn report(self) -> eyre::Report {
            match self {
                Self::Local(error) => error.into(),
                Self::Remote(error) => remote_failure(error),
            }
        }
    }
    let Stdin {
        chunks: mut input,
        kind,
    } = input;
    let settled = {
        let upstream = async {
            let mut carried = Carried::Nothing;
            while let Some(chunk) = input.recv().await {
                let chunk = match chunk {
                    Ok(chunk) => chunk,
                    Err(error) => return Err(UpFailed::Local(error)),
                };
                // Flushed per chunk: a framed half may hold a frame until asked.
                let sent = async {
                    writer.write_all(&chunk).await?;
                    writer.flush().await
                };
                if let Err(error) = sent.await {
                    return Err(UpFailed::Remote(error));
                }
                if !chunk.is_empty() {
                    carried = Carried::Data;
                }
            }
            match writer.shutdown().await {
                Ok(()) => Ok(carried),
                Err(error) => Err(UpFailed::Remote(error)),
            }
        };
        // Owns the reader and the output and hands both back, so the run can close the one and watch
        // the other once the download is whole, while the upload goes on.
        let downstream = async {
            let (mut reader, mut output) = (RemoteReader(reader), output);
            let copied = async {
                io::copy(&mut reader, &mut output)
                    .await
                    .map_err(read_failure)?;
                output.flush().await?;
                Ok::<(), eyre::Report>(())
            }
            .await;
            (copied, reader, output)
        };
        // One upload future for the whole run: a chunk it took from stdin, or a frame half written, is
        // never dropped and read again. A pending stdout write can likewise leave remote bytes inside the
        // copy's buffer, so the same download future runs through stdin's end.
        tokio::pin!(upstream, downstream);
        tokio::select! {
            (copied, reader, mut output) = &mut downstream => match (copied, kind) {
                (Err(error), _) => Settled::Cut(Err(error)),
                (Ok(()), StdinKind::Terminal) => Settled::Cut(Ok(())),
                (Ok(()), StdinKind::Piped) => match output.close() {
                    Err(error) => Settled::Cut(Err(error.into())),
                    Ok(()) => {
                        let mut reader = reader;
                        tokio::select! {
                            up = &mut upstream => match up {
                                Ok(carried) => Settled::Uploaded(carried, reader),
                                Err(failed) => Settled::Cut(Err(failed.report())),
                            },
                            // Nothing can land before the upload's end, so any answer here is the
                            // connection ending without it.
                            landed = reader.0.landed() => Settled::Cut(Err(match landed {
                                Err(error) => remote_failure(error),
                                Ok(()) => remote_failure(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "landed before the upload ended",
                                )),
                            })),
                        }
                    }
                },
            },
            up = &mut upstream => match up {
                // stdin ended first (a piped, finite input): the host's remaining output still drains.
                Ok(carried) => match (&mut downstream).await {
                    (Ok(()), reader, _) => Settled::Uploaded(carried, reader),
                    (Err(error), _, _) => Settled::Done(error),
                },
                Err(failed) => Settled::Cut(Err(failed.report())),
            },
        }
    };
    match settled {
        Settled::Cut(result) => {
            writer.cut();
            result
        }
        Settled::Done(error) => Err(error),
        Settled::Uploaded(Carried::Nothing, _) => Ok(()),
        Settled::Uploaded(Carried::Data, mut reader) => {
            let landed = tokio::select! {
                // Delivery first: a far side that holds the upload and then closes still exits 0.
                biased;
                delivered = writer.delivered() => delivered,
                landed = reader.0.landed() => landed,
            };
            landed.map_err(remote_failure)
        }
    }
}

/// The upload half of a forwarded stream, as the pump ends it: `shutdown` is its clean end, and `cut`
/// ends it so the far service reads a reset.
pub(crate) trait Upload: io::AsyncWrite + Unpin {
    /// End the upload as cut off.
    fn cut(self);

    /// After `shutdown`, resolve once the far side holds the whole upload and its end, or fail when it
    /// never will. Pending forever where the word comes on the download half instead.
    fn delivered(self) -> impl Future<Output = io::Result<()>>;
}

/// The download half of a forwarded stream: the host's bytes, and the word that the upload landed.
pub(crate) trait Download: io::AsyncRead + Unpin {
    /// After the download's end, resolve with the word that the far side holds the whole upload and its
    /// end, or fail once the connection ends without it. Where the word comes on the upload half
    /// instead, this only fails, once the connection ends.
    fn landed(&mut self) -> impl Future<Output = io::Result<()>>;
}

/// This run's stdin: its chunks, and what kind of input it is.
pub(crate) struct Stdin {
    pub(crate) chunks: mpsc::Receiver<io::Result<Vec<u8>>>,
    pub(crate) kind: StdinKind,
}

impl Stdin {
    /// This process's stdin, read on its own thread (see [`stdin_chunks`]).
    pub(crate) fn open() -> eyre::Result<Self> {
        let kind = if std::io::stdin().is_terminal() {
            StdinKind::Terminal
        } else {
            StdinKind::Piped
        };
        Ok(Self {
            chunks: stdin_chunks()?,
            kind,
        })
    }
}

/// Whether a person types stdin, which decides the upload when the download ends first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StdinKind {
    /// A terminal: the run ends with the download, and the upload is cut.
    Terminal,
    /// A file, a pipe or a ProxyCommand's pipe: the upload runs to stdin's end and waits to land.
    Piped,
}

/// Where the download goes, closed for good once it is whole.
pub(crate) trait Output: io::AsyncWrite + Unpin {
    /// Close it now, so whatever reads it sees its end before this process exits.
    fn close(&mut self) -> io::Result<()>;
}

/// This process's stdout.
#[derive(Debug)]
pub(crate) struct Stdout(io::Stdout);

impl Default for Stdout {
    fn default() -> Self {
        Self(io::stdout())
    }
}

impl io::AsyncWrite for Stdout {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl Output for Stdout {
    /// The descriptor itself, not tokio's handle, whose shutdown only flushes: the pipe a ProxyCommand
    /// host reads ends here. Called once the download is flushed.
    fn close(&mut self) -> io::Result<()> {
        use std::os::fd::AsFd as _;

        close_onto_null(std::io::stdout().as_fd())
    }
}

/// End what `fd` names for its reader, then point `fd` at `/dev/null`, so the number stays taken:
/// nothing opened later becomes this process's stdout, and a later write goes nowhere rather than
/// failing.
///
/// A pipe ends for its reader only when its last write descriptor closes, and a socket only when every
/// descriptor naming it closes, unless its writing is shut down. So a socket (one a host hands over as
/// both stdin and stdout, as socat and inetd do) has its writing shut down first, which ends it for the
/// reader however many descriptors name it. A pipe that another descriptor also names, such as stderr
/// under `2>&1`, cannot be ended from here: its reader sees the end when this process exits.
fn close_onto_null(fd: std::os::fd::BorrowedFd<'_>) -> io::Result<()> {
    use std::os::fd::AsRawFd as _;

    // SAFETY: `fd` is open for the call; `shutdown` changes no memory, only the socket's state. Any
    // descriptor that is not a socket answers ENOTSOCK and is left to the `dup2`, as is a socket
    // whose peer is already gone (ENOTCONN), whose reader has its end already.
    if unsafe { libc::shutdown(fd.as_raw_fd(), libc::SHUT_WR) } < 0 {
        let error = io::Error::last_os_error();
        if !matches!(error.raw_os_error(), Some(libc::ENOTSOCK | libc::ENOTCONN)) {
            return Err(error);
        }
    }
    let null = std::fs::OpenOptions::new().write(true).open("/dev/null")?;
    // SAFETY: both descriptors are open for the call; `dup2` only makes `fd` name what `null` names.
    if unsafe { libc::dup2(null.as_raw_fd(), fd.as_raw_fd()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The upload half of a transport stream, held by the own bind.
pub(crate) struct Stream<H>(pub(crate) H);

impl<W: io::AsyncWrite + bifrost::WriteEnd + Unpin> Upload for Stream<W> {
    fn cut(mut self) {
        self.0.abort();
    }

    /// The transport's own word, so exit 0 means the same on the own bind as through `serve`.
    fn delivered(self) -> impl Future<Output = io::Result<()>> {
        bifrost::WriteEnd::delivered(self.0)
    }
}

impl<W: io::AsyncWrite + Unpin> io::AsyncWrite for Stream<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

/// The own bind's download half, with the session it rides: the session closing is the connection
/// ending, which a read half that has already reached its end can no longer report.
pub(crate) struct OwnRead<'s, S: Session> {
    pub(crate) half: S::Read,
    pub(crate) session: &'s S,
}

impl<S: Session> Download for OwnRead<'_, S> {
    /// The word that the upload landed comes on the upload half, so this only fails, once the session
    /// closes: the host cut it (on a revoke or an expiry), or the path to it failed.
    async fn landed(&mut self) -> io::Result<()> {
        self.session.wait_closed().await;
        Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "session closed",
        ))
    }
}

impl<S: Session> io::AsyncRead for OwnRead<'_, S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.half).poll_read(cx, buf)
    }
}

impl Upload for swoosh::serve::control_codec::OpenWrite {
    fn cut(self) {
        self.abort();
    }

    /// The resident's Landed comes on the read half.
    fn delivered(self) -> impl Future<Output = io::Result<()>> {
        core::future::pending()
    }
}

impl Download for swoosh::serve::control_codec::OpenRead {
    fn landed(&mut self) -> impl Future<Output = io::Result<()>> {
        swoosh::serve::control_codec::OpenRead::landed(self)
    }
}

/// `io::copy` returns either endpoint's error as `io::Error`; only the remote reader gets this tag.
struct RemoteReader<R>(R);

impl<R: io::AsyncRead + Unpin> io::AsyncRead for RemoteReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.get_mut().0).poll_read(cx, buf) {
            Poll::Ready(Err(error)) => {
                Poll::Ready(Err(io::Error::new(error.kind(), RemoteRead(error))))
            }
            other => other,
        }
    }
}

/// The tag preserves provenance without changing the transport's diagnostic text.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
struct RemoteRead(io::Error);

/// A copy's local writer error must remain local, regardless of the remote session's state.
fn read_failure(error: io::Error) -> eyre::Report {
    if error
        .get_ref()
        .is_some_and(|cause| cause.is::<RemoteRead>())
    {
        remote_failure(error)
    } else {
        error.into()
    }
}

/// A failed remote read, write or half-close says only that this CLI stream ended, not why.
fn remote_failure(error: io::Error) -> eyre::Report {
    tracing::debug!(cause = %swoosh::escape::Escaped(&swoosh::escape::causes(&error)), "connection lost");
    ConnectionLost.into()
}

/// This process's stdin, read on a thread of its own and handed over in chunks; the channel closes at
/// the end of input or after a read error.
///
/// Not tokio's stdin: that reads on the runtime's blocking pool, and the runtime waits for every blocking
/// read before the process can exit, so a run that has ended would hang until the next keystroke. This
/// thread is never joined: a read it is parked in ends with the process.
pub fn stdin_chunks() -> eyre::Result<mpsc::Receiver<io::Result<Vec<u8>>>> {
    // One chunk in flight: the reader waits for the stream to take a chunk before reading the next, so
    // a slow host holds back stdin rather than this process buffering it.
    let (sender, receiver) = mpsc::channel(1);
    std::thread::Builder::new()
        .name("stdin".to_owned())
        .spawn(move || {
            let mut stdin = std::io::stdin().lock();
            let mut buffer = vec![0_u8; 16 * 1024];
            loop {
                let chunk = match stdin.read(&mut buffer) {
                    Ok(0) => return,
                    Ok(read) => Ok(buffer[..read].to_vec()),
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) => Err(error),
                };
                let failed = chunk.is_err();
                if sender.blocking_send(chunk).is_err() || failed {
                    return;
                }
            }
        })?;
    Ok(receiver)
}

#[cfg(test)]
mod tests {
    use core::future::Future as _;
    use core::pin::Pin;
    use core::task::{Context, Poll};

    use bifrost::{Session as _, Transport as _};
    use futures::FutureExt as _;
    use swoosh::contacts::Contacts;
    use swoosh::testkit::HostilePeer;
    use tokio::io;
    use tokio::sync::{mpsc, oneshot};

    use super::{Machine, To, connect};

    /// A gate's refusal detail holding a carriage return, an ESC CSI sequence and a bidi override.
    const HOSTILE: &str = "no\r\u{1b}[2Kforwarding 127.0.0.1:1 to x\u{202e}";
    /// [`HOSTILE`] as it prints.
    const ESCAPED: &str = r"no\r\u{1b}[2Kforwarding 127.0.0.1:1 to x\u{202e}";

    #[test]
    fn a_cut_has_no_printable_source() {
        let report = eyre::Report::new(super::ConnectionLost);
        assert_eq!(report.chain().count(), 1);
        assert_eq!(format!("error: {report:#}\n"), "error: connection lost\n");
        assert_eq!(
            format!("error: {:#}\n", super::escaped(report)),
            "error: connection lost\n"
        );
    }

    /// A test half: cut is a drop, and a finished upload is delivered at once, on the upload half.
    struct Plain<H>(H);
    impl<W: io::AsyncWrite + Unpin> super::Upload for Plain<W> {
        fn cut(self) {}
        async fn delivered(self) -> io::Result<()> {
            Ok(())
        }
    }
    impl<R: io::AsyncRead + Unpin> super::Download for Plain<R> {
        fn landed(&mut self) -> impl Future<Output = io::Result<()>> {
            core::future::pending()
        }
    }

    /// `input` as a piped stdin.
    fn piped(input: mpsc::Receiver<io::Result<Vec<u8>>>) -> super::Stdin {
        super::Stdin {
            chunks: input,
            kind: super::StdinKind::Piped,
        }
    }

    /// `input` as a terminal's stdin.
    fn terminal(input: mpsc::Receiver<io::Result<Vec<u8>>>) -> super::Stdin {
        super::Stdin {
            chunks: input,
            kind: super::StdinKind::Terminal,
        }
    }

    /// Test outputs have no descriptor to close.
    impl super::Output for io::Sink {
        fn close(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl super::Output for &mut Vec<u8> {
        fn close(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl super::Output for FailedWriter {
        fn close(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl<W: io::AsyncWrite + Unpin> io::AsyncWrite for Plain<W> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(cx, buf)
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }
        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }
    impl<R: io::AsyncRead + Unpin> io::AsyncRead for Plain<R> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut io::ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_read(cx, buf)
        }
    }

    /// Real closure futures bracket controlled I/O faults; the pump must not depend on their readiness.
    async fn sessions() -> (bifrost_mem::MemSession, bifrost_mem::MemSession) {
        let first = bifrost_mem::MemTransport::bind();
        let second = bifrost_mem::MemTransport::bind();
        let session = first.connect(second.local_addr()).await.unwrap();
        let peer = second.accept().await.unwrap();
        (session, peer)
    }

    fn fault() -> io::Error {
        io::Error::other(HOSTILE)
    }

    struct FailedReader;
    impl io::AsyncRead for FailedReader {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &mut io::ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Err(fault()))
        }
    }

    /// Never wakes: every tested failure is ready on the other endpoint, so a single poll must finish.
    struct PendingReader;
    impl io::AsyncRead for PendingReader {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &mut io::ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    #[derive(Clone, Copy)]
    enum WriteFailure {
        Write,
        Flush,
        Shutdown,
    }

    struct FailedWriter(WriteFailure);
    impl io::AsyncWrite for FailedWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(if matches!(self.0, WriteFailure::Write) {
                Err(fault())
            } else {
                Ok(buf.len())
            })
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(if matches!(self.0, WriteFailure::Flush) {
                Err(fault())
            } else {
                Ok(())
            })
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(if matches!(self.0, WriteFailure::Shutdown) {
                Err(fault())
            } else {
                Ok(())
            })
        }
    }

    /// The oneshot forces the reader's result to arrive only after half-close, without scheduling races.
    struct HalfCloseWriter(Option<oneshot::Sender<()>>);
    impl io::AsyncWrite for HalfCloseWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            if let Some(closed) = self.0.take() {
                let _ = closed.send(());
            }
            Poll::Ready(Ok(()))
        }
    }

    struct AfterHalfClose<R> {
        closed: Option<oneshot::Receiver<()>>,
        reader: R,
    }
    impl<R: io::AsyncRead + Unpin> io::AsyncRead for AfterHalfClose<R> {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut io::ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            if let Some(closed) = &mut this.closed {
                match Pin::new(closed).poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(result) => {
                        result.expect("the writer half-closed");
                        this.closed = None;
                    }
                }
            }
            Pin::new(&mut this.reader).poll_read(cx, buf)
        }
    }

    fn after_half_close<R>(reader: R) -> (HalfCloseWriter, AfterHalfClose<R>) {
        let (closed, waiting) = oneshot::channel();
        (
            HalfCloseWriter(Some(closed)),
            AfterHalfClose {
                closed: Some(waiting),
                reader,
            },
        )
    }

    fn assert_remote(result: eyre::Result<()>) {
        let report = result.unwrap_err();
        assert!(report.is::<super::ConnectionLost>(), "{report:?}");
        assert_eq!(report.chain().count(), 1);
        assert_eq!(format!("error: {report:#}\n"), "error: connection lost\n");
        assert_eq!(
            format!("error: {:#}\n", super::escaped(report)),
            "error: connection lost\n"
        );
    }

    fn assert_local(result: eyre::Result<()>) {
        let report = result.unwrap_err();
        assert!(!report.is::<super::ConnectionLost>());
        assert_eq!(
            report.downcast_ref::<io::Error>().unwrap().to_string(),
            HOSTILE
        );
    }

    #[tokio::test]
    async fn remote_reads_are_opaque_before_session_closure_before_and_after_half_close() {
        let (session, _peer) = sessions().await;
        assert!(session.wait_closed().now_or_never().is_none());
        let (_stdin, input) = mpsc::channel(1);
        assert_remote(
            super::pump_stdio(
                Plain(io::sink()),
                Plain(FailedReader),
                piped(input),
                io::sink(),
            )
            .now_or_never()
            .expect("a remote read fails without waiting for closure"),
        );
        let (stdin, input) = mpsc::channel(1);
        drop(stdin);
        let (writer, reader) = after_half_close(FailedReader);
        assert_remote(
            super::pump_stdio(Plain(writer), Plain(reader), piped(input), io::sink())
                .now_or_never()
                .expect("the retained copy preserves the reader's tag after half-close"),
        );
        assert!(session.wait_closed().now_or_never().is_none());
    }

    #[tokio::test]
    async fn remote_write_and_shutdown_failures_are_opaque_before_session_closure() {
        let (session, _peer) = sessions().await;
        assert!(session.wait_closed().now_or_never().is_none());
        for at in [WriteFailure::Write, WriteFailure::Shutdown] {
            let (stdin, input) = mpsc::channel(1);
            if matches!(at, WriteFailure::Write) {
                stdin.try_send(Ok(vec![1])).unwrap();
            }
            drop(stdin);
            assert_remote(
                super::pump_stdio(
                    Plain(FailedWriter(at)),
                    Plain(PendingReader),
                    piped(input),
                    io::sink(),
                )
                .now_or_never()
                .expect("remote writes fail without waiting for closure"),
            );
        }
        assert!(session.wait_closed().now_or_never().is_none());
    }

    #[tokio::test]
    async fn local_stdin_stdout_write_and_flush_errors_stay_local_after_closure() {
        let (session, _peer) = sessions().await;
        session.close();
        assert!(session.wait_closed().now_or_never().is_some());
        let (_stdin, input) = {
            let (stdin, input) = mpsc::channel(1);
            stdin.try_send(Err(fault())).unwrap();
            (stdin, input)
        };
        assert_local(
            super::pump_stdio(
                Plain(io::sink()),
                Plain(PendingReader),
                piped(input),
                io::sink(),
            )
            .now_or_never()
            .expect("a local stdin error is ready"),
        );
        for at in [WriteFailure::Write, WriteFailure::Flush] {
            let (_stdin, input) = mpsc::channel(1);
            assert_local(
                super::pump_stdio(
                    Plain(io::sink()),
                    Plain(&b"out"[..]),
                    piped(input),
                    FailedWriter(at),
                )
                .now_or_never()
                .expect("a local stdout error is ready"),
            );
            let (stdin, input) = mpsc::channel(1);
            drop(stdin);
            let (writer, reader) = after_half_close(&b"out"[..]);
            assert_local(
                super::pump_stdio(Plain(writer), Plain(reader), piped(input), FailedWriter(at))
                    .now_or_never()
                    .expect("a post-half-close stdout error stays local"),
            );
        }
    }

    #[tokio::test]
    async fn a_clean_remote_eof_on_a_terminal_ends_with_stdin_still_open() {
        let (_stdin, input) = mpsc::channel(1);
        assert!(
            super::pump_stdio(
                Plain(io::sink()),
                Plain(io::empty()),
                terminal(input),
                io::sink()
            )
            .now_or_never()
            .expect("remote EOF does not wait for stdin")
            .is_ok()
        );
    }

    #[tokio::test]
    async fn stdin_eof_half_closes_then_drains_remote_output() {
        let (stdin, input) = mpsc::channel(1);
        stdin.try_send(Ok(b"in".to_vec())).unwrap();
        drop(stdin);
        let (writer, reader) = after_half_close(&b"drained"[..]);
        let mut output = Vec::new();
        assert!(
            super::pump_stdio(Plain(writer), Plain(reader), piped(input), &mut output)
                .now_or_never()
                .expect("half-close makes the remaining output ready")
                .is_ok()
        );
        assert_eq!(output, b"drained");
    }

    #[tokio::test]
    async fn stdin_eof_preserves_bytes_already_buffered_behind_pending_stdout() {
        use core::cell::Cell;

        struct CountedReader<'a> {
            remaining: &'a [u8],
            consumed: &'a Cell<usize>,
        }
        impl io::AsyncRead for CountedReader<'_> {
            fn poll_read(
                mut self: Pin<&mut Self>,
                _: &mut Context<'_>,
                buf: &mut io::ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                let count = self.remaining.len().min(buf.remaining());
                buf.put_slice(&self.remaining[..count]);
                self.remaining = &self.remaining[count..];
                self.consumed.set(self.consumed.get() + count);
                Poll::Ready(Ok(()))
            }
        }

        // The receiver holds its registered waker across polls. Output cannot accept any byte until
        // the test has observed both buffered remote input and the successful upstream half-close.
        struct BlockedOutput<'a> {
            release: Option<oneshot::Receiver<()>>,
            pending: &'a Cell<usize>,
            flushed: &'a Cell<usize>,
            bytes: &'a mut Vec<u8>,
        }
        impl io::AsyncWrite for BlockedOutput<'_> {
            fn poll_write(
                self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                bytes: &[u8],
            ) -> Poll<io::Result<usize>> {
                let this = self.get_mut();
                if let Some(release) = &mut this.release {
                    match Pin::new(release).poll(cx) {
                        Poll::Pending => {
                            this.pending.set(this.pending.get() + 1);
                            return Poll::Pending;
                        }
                        Poll::Ready(result) => {
                            result.expect("the test released stdout");
                            this.release = None;
                        }
                    }
                }
                this.bytes.extend_from_slice(bytes);
                Poll::Ready(Ok(bytes.len()))
            }
            fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                self.flushed.set(self.flushed.get() + 1);
                Poll::Ready(Ok(()))
            }
            fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                panic!("the local stdout must not be shut down")
            }
        }
        impl super::Output for BlockedOutput<'_> {
            fn close(&mut self) -> io::Result<()> {
                panic!("an upload that ends first never closes stdout")
            }
        }

        let payload = b"buffered before stdin eof, delivered exactly once";
        let consumed = Cell::new(0);
        let pending = Cell::new(0);
        let flushed = Cell::new(0);
        let mut bytes = Vec::new();
        let (stdin, input) = mpsc::channel(1);
        let (closed, mut half_close) = oneshot::channel();
        let (release, waiting) = oneshot::channel();
        let completed_before_release;
        {
            let reader = CountedReader {
                remaining: payload,
                consumed: &consumed,
            };
            let output = BlockedOutput {
                release: Some(waiting),
                pending: &pending,
                flushed: &flushed,
                bytes: &mut bytes,
            };
            let pump = super::pump_stdio(
                Plain(HalfCloseWriter(Some(closed))),
                Plain(reader),
                piped(input),
                output,
            );
            tokio::pin!(pump);
            let mut cx = Context::from_waker(futures::task::noop_waker_ref());
            assert!(pump.as_mut().poll(&mut cx).is_pending());
            assert_eq!(consumed.get(), payload.len(), "remote bytes were consumed");
            assert!(pending.get() > 0, "stdout write returned Pending");
            assert!(
                !stdin.is_closed(),
                "stdin stays open until output is pending"
            );
            assert!(matches!(
                half_close.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));

            drop(stdin);
            completed_before_release = match pump.as_mut().poll(&mut cx) {
                Poll::Pending => false,
                Poll::Ready(result) => {
                    result.unwrap();
                    true
                }
            };
            assert_eq!(
                half_close.try_recv(),
                Ok(()),
                "upstream shut down before stdout release"
            );
            let released = release.send(());
            if !completed_before_release {
                assert_eq!(flushed.get(), 0, "buffered output has not flushed");
                released.expect("stdout still waits for release");
                assert!(matches!(pump.as_mut().poll(&mut cx), Poll::Ready(Ok(()))));
            }
        }
        assert_eq!(bytes, payload, "buffered remote bytes arrive exactly once");
        assert!(
            !completed_before_release,
            "the pump waits for pending stdout"
        );
        assert_eq!(flushed.get(), 2, "copy and final stdout flush both succeed");
    }

    #[tokio::test]
    async fn a_cut_cause_is_escaped_and_separate_in_explicit_diagnostics_only() {
        use std::sync::{Arc, Mutex};

        use tracing::instrument::WithSubscriber as _;

        // Callsite interest is process-global. Other tests' scoped subscribers must not race this
        // exact event-count assertion; keep both production-origin calls and all checks in the child.
        const CHILD: &str = "SWOOSH_TEST_DIAGNOSTIC_CAPTURE";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "commands::connect::tests::a_cut_cause_is_escaped_and_separate_in_explicit_diagnostics_only",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .stdin(std::process::Stdio::null())
                .output()
                .unwrap();
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(
                output.status.success(),
                "{stdout}{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(stdout.contains("1 passed"), "{stdout}");
            return;
        }

        // The subscriber owns its writer; the test reads the shared bytes after dispatch.
        #[derive(Clone)]
        struct Capture(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for Capture {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        for directives in [None, Some("debug")] {
            let bytes = Arc::new(Mutex::new(Vec::new()));
            let capture = Capture(Arc::clone(&bytes));
            let subscriber = tracing_subscriber::fmt()
                .with_env_filter(crate::log_filter(directives.map(str::to_owned)))
                .without_time()
                .with_ansi(false)
                .with_writer(move || Capture::clone(&capture))
                .finish();
            let report = async { super::remote_failure(fault()) }
                .with_subscriber(subscriber)
                .await;
            assert_eq!(format!("error: {report:#}\n"), "error: connection lost\n");
            let printed = String::from_utf8(Vec::clone(&bytes.lock().unwrap())).unwrap();
            if directives.is_some() {
                assert!(printed.contains(ESCAPED), "{printed:?}");
                assert!(!printed.contains(HOSTILE));
                assert_eq!(printed.lines().count(), 1);
            } else {
                assert_eq!(printed, "");
            }
        }
    }

    /// Reach a peer whose gate refuses with [`HOSTILE`], sinking the bytes into `to`.
    async fn refused(to: To) -> eyre::Report {
        failed(HostilePeer::RefusesAtTheGate(HOSTILE), to).await
    }

    /// Reach `host`, sinking the bytes into `to`, and return the error the reach fails with.
    async fn failed(host: HostilePeer, to: To) -> eyre::Report {
        let node = bifrost::Node::new(host, bifrost::NoDiscovery);
        let machine = HostilePeer::node_id()
            .to_string()
            .parse::<swoosh::peer::Peer>()
            .expect("a raw key parses as a Peer")
            .machine(&Contacts::default())
            .expect("a key is one machine");
        let service = "db".parse().expect("db is a service name");
        connect(
            &node,
            &swoosh::peers::Peers::new(&node),
            &Contacts::default(),
            &machine,
            service,
            None,
            None,
            swoosh::peers::Presents::Standing(None),
            to,
        )
        .await
        .expect_err("a refused reach is an error")
    }

    // A forward whose gate refuses prints the refusal, and its detail is the peer's text: escaped, on one
    // line, so it cannot erase the error and draw a `forwarding` line in its place.
    #[tokio::test]
    async fn a_hostile_forward_refusal_prints_escaped() {
        let error = refused(To::Port(1)).await;
        assert_eq!(
            format!("{error:#}"),
            format!(
                "reached {}, but refused: unavailable: {ESCAPED}",
                HostilePeer::node_id()
            )
        );
    }

    // The stdio bridge (`-`, and `swoosh ssh`'s ProxyCommand through it) prints the same refusal the
    // same way.
    #[tokio::test]
    async fn a_hostile_stdio_refusal_prints_escaped() {
        let error = refused(To::Stdout).await;
        assert_eq!(
            format!("{error:#}"),
            format!("stream refused: unavailable: {ESCAPED}")
        );
    }

    // A host that ends the stream before it answers (it died mid-dial) prints the exchange's own cause,
    // with no word in front of it, and the same line on both sinks.
    #[tokio::test]
    async fn a_host_that_hangs_up_before_answering_prints_the_bare_cause() {
        for to in [To::Port(1), To::Stdout] {
            let error = failed(HostilePeer::HangsUp, To::clone(&to)).await;
            assert_eq!(format!("{error:#}"), "early eof", "reaching to {to:?}");
        }
    }

    #[test]
    fn to_parses_each_of_the_three_forms_and_rejects_the_rest() {
        assert_eq!("5432".parse::<To>().expect("a port parses"), To::Port(5432));
        assert_eq!("-".parse::<To>().expect("stdout parses"), To::Stdout);
        assert_eq!(
            "unix:/run/x.sock".parse::<To>().expect("unix parses"),
            To::UnixListener("/run/x.sock".into())
        );
        // A bare path, a source-only scheme, and out-of-range ports are hard errors, never a silent
        // misparse (a bare path must never look like a port, `fifo:`/`file:` are the shell's job).
        for bad in [
            "/tmp/out",
            "fifo:/tmp/x",
            "file:out",
            "0",
            "70000",
            "web",
            "",
        ] {
            assert!(bad.parse::<To>().is_err(), "`{bad}` must be rejected");
        }
        // The refusal spells the three ends the way the missing-end line does, and echoes nothing typed.
        let refused = "web".parse::<To>().expect_err("web is no local end");
        assert_eq!(
            refused.to_string(),
            "a local end is a port (5432), unix:<path>, or - for stdout"
        );
    }

    /// A forward to `typed`, resolved against a book holding your device `me/nas` and bob's `bob/nas`,
    /// both at the scripted peer's key in turn, whose gate answers `script`.
    async fn forwarded(
        typed: &str,
        script: Vec<swoosh::testkit::Script>,
    ) -> (eyre::Report, swoosh::testkit::ScriptedPeer) {
        let key = bifrost::NodeId::from_ed25519_secret(&[0x66; 32]);
        let mut contacts = Contacts::default();
        contacts
            .save(&typed.parse().expect("a machine name"), key)
            .expect("the name is free");
        let machine = typed
            .parse::<swoosh::peer::Peer>()
            .expect("a peer")
            .machine(&contacts)
            .expect("one machine");
        let peer = swoosh::testkit::ScriptedPeer::new(key, script);
        let node = bifrost::Node::new(peer.clone(), bifrost::NoDiscovery);
        let error = connect(
            &node,
            &swoosh::peers::Peers::new(&node),
            &contacts,
            &machine,
            "ssh".parse().expect("a service"),
            None,
            None,
            swoosh::peers::Presents::Standing(None),
            To::Port(1),
        )
        .await
        .expect_err("a refused forward is an error");
        (error, peer)
    }

    // A forward refused by one of your devices asks it why, on the same session, and says what it found:
    // here the device's list lacks the service, so the line names the form that adds it there.
    #[tokio::test]
    async fn a_refused_forward_to_your_device_asks_it_why() {
        use swoosh::testkit::Script;

        let (error, peer) = forwarded(
            "me/nas",
            vec![
                Script::Refuse(bifrost::Refusal::NotAdmitted),
                Script::Lists(vec!["ping"]),
            ],
        )
        .await;
        assert_eq!(
            format!("{error:#}"),
            "me/nas does not serve ssh\n  Only nas can add it; on nas, run:\n    swoosh service add ssh"
        );
        let asked: Vec<String> = peer
            .requests()
            .into_iter()
            .map(|request| request.service)
            .collect();
        assert_eq!(asked, ["ssh", "control.services"]);
        assert_eq!(
            peer.dials(),
            2,
            "the follow-up asks over a connection of its own"
        );
    }

    // A forward refused by anyone else's machine names both causes and asks nothing.
    #[tokio::test]
    async fn a_refused_forward_to_a_contact_asks_nothing() {
        use swoosh::testkit::Script;

        let (error, peer) = forwarded(
            "bob/nas",
            vec![Script::Refuse(bifrost::Refusal::NotAdmitted)],
        )
        .await;
        assert_eq!(
            format!("{error:#}"),
            "bob/nas refused ssh\n  It does not serve ssh, or its owner has not shared ssh with you."
        );
        assert_eq!(
            peer.requests().len(),
            1,
            "nothing is asked of a contact's machine"
        );
    }

    /// `forward <port>` by own bind for `me/nas`'s `ssh`, on `node` and its run's `peers`: admitted on
    /// one stream, then listening while `clients` connect, with the owner's sweep driven beside it as a
    /// run drives it, for at most `idle` past a row's bound. Returns the line the run ended with.
    async fn ported<'n>(
        node: &'n bifrost::Node<swoosh::testkit::ScriptedPeer, bifrost::NoDiscovery>,
        peers: &swoosh::peers::Peers<'n, swoosh::testkit::ScriptedPeer, bifrost::NoDiscovery>,
        idle: core::time::Duration,
        clients: impl AsyncFnOnce(core::net::SocketAddr),
    ) -> eyre::Report {
        let contacts = crate::commands::through_serve::tests::book();
        let machine = crate::commands::through_serve::tests::machine(&contacts, "me/nas");
        let service = "ssh".parse().expect("a service");
        let refused = super::Refused {
            machine: &machine,
            service: &service,
            slot1: &None,
            slot2: &None,
        };
        let pipes = super::OwnPipes {
            node,
            peers,
            refused: &refused,
            presents: swoosh::peers::Presents::Standing(None),
        };
        let (end, _, _) = pipes.open().await.expect("admitted");
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("a free port");
        let local = listener.local_addr().expect("its address");
        let connecting = async {
            clients(local).await;
            core::future::pending::<()>().await;
        };
        let bound = crate::commands::through_serve::tests::ROW_BOUND + idle;
        tokio::time::timeout(bound, async {
            tokio::select! {
                ended = pipes.forward(listener, end) => ended,
                never = peers.sweep() => match never {},
                () = connecting => unreachable!(),
            }
        })
        .await
        .expect("the run ended")
    }

    /// A peer at `me/nas`'s key whose gate answers `script`.
    fn nas(script: Vec<swoosh::testkit::Script>) -> swoosh::testkit::ScriptedPeer {
        let contacts = crate::commands::through_serve::tests::book();
        let key = crate::commands::through_serve::tests::machine(&contacts, "me/nas").key();
        swoosh::testkit::ScriptedPeer::new(key, script)
    }

    /// One local client that uploads nothing, closes its upload and reads to the end.
    async fn client(local: core::net::SocketAddr) {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let mut client = tokio::net::TcpStream::connect(local)
            .await
            .expect("connect");
        let _ = client.shutdown().await;
        let _ = client.read_to_end(&mut Vec::new()).await;
    }

    /// By own bind a port's streams ride the Bulk lane: with the machine's Main lane full, the admission
    /// and a pipe still open, on a held session of their own.
    #[tokio::test]
    async fn a_port_by_own_bind_rides_the_bulk_lane() {
        use swoosh::peers::{Hints, Lane, Presents};
        use swoosh::testkit::Script;

        let mut script = vec![Script::Holds; 64];
        script.extend([Script::Holds, Script::Ends]);
        let peer = nas(script);
        let node = bifrost::Node::new(peer.clone(), bifrost::NoDiscovery);
        let peers = swoosh::peers::Peers::new(&node);
        let mut main = Vec::new();
        for _ in 0..64 {
            main.push(
                peers
                    .open(
                        peer.peer(),
                        Hints::NONE,
                        "ssh".parse().expect("a service"),
                        Lane::Main,
                        Presents::Standing(None),
                    )
                    .await
                    .expect("below the Main cap"),
            );
        }
        let ended = ported(&node, &peers, core::time::Duration::ZERO, async |local| {
            client(local).await;
            peer.cut();
        })
        .await;
        assert!(ended.is::<super::ConnectionLost>(), "{ended:#}");
        assert_eq!(peer.dials(), 2, "one session per lane");
    }

    /// The run watches the session its latest stream rode: once the owner's sweep has let the admission's
    /// idle session go, the next pipe dials a session of its own, and that session's cut alone ends the
    /// run with `connection lost`.
    #[tokio::test(start_paused = true)]
    async fn a_port_by_own_bind_watches_the_session_its_latest_pipe_rode() {
        use swoosh::testkit::Script;

        let peer = nas(vec![Script::Holds, Script::Holds]);
        let node = bifrost::Node::new(peer.clone(), bifrost::NoDiscovery);
        let peers = swoosh::peers::Peers::new(&node);
        // Past the owner's five idle minutes and its next sweep.
        let idle = core::time::Duration::from_secs(7 * 60);
        let ended = ported(&node, &peers, idle, async |local| {
            tokio::time::sleep(idle).await;
            // Real time from here: a paused clock idling on the loopback connect below would jump
            // straight to the row's bound.
            tokio::time::resume();
            // Held open, so the pipe stays on the session it rode.
            let _held = tokio::net::TcpStream::connect(local)
                .await
                .expect("connect");
            while peer.requests().len() < 2 {
                tokio::time::sleep(core::time::Duration::from_millis(10)).await;
            }
            assert_eq!(peer.dials(), 2, "the pipe rode a session of its own");
            peer.cut_nth(1);
            core::future::pending::<()>().await;
        })
        .await;
        assert!(ended.is::<super::ConnectionLost>(), "{ended:#}");
    }

    /// A host cut ends a port by own bind with `connection lost` while a pipe rides the session, as a
    /// lease end that cuts it does.
    #[tokio::test]
    async fn a_host_cut_ends_a_port_by_own_bind_with_connection_lost() {
        use swoosh::testkit::Script;

        let peer = nas(vec![Script::Holds, Script::Holds]);
        let node = bifrost::Node::new(peer.clone(), bifrost::NoDiscovery);
        let peers = swoosh::peers::Peers::new(&node);
        let ended = ported(&node, &peers, core::time::Duration::ZERO, async |local| {
            let _held = tokio::net::TcpStream::connect(local)
                .await
                .expect("connect");
            while peer.requests().len() < 2 {
                tokio::time::sleep(core::time::Duration::from_millis(10)).await;
            }
            peer.cut();
            core::future::pending::<()>().await;
        })
        .await;
        assert!(ended.is::<super::ConnectionLost>(), "{ended:#}");
    }

    /// A later pipe's `NotAdmitted` ends a port by own bind with the dial refusal, one of your devices
    /// asked why, as the admission's refusal would.
    #[tokio::test]
    async fn a_later_not_admitted_ends_a_port_by_own_bind_with_the_dial_refusal() {
        use swoosh::testkit::Script;

        let peer = nas(vec![
            Script::Holds,
            Script::Refuse(bifrost::Refusal::NotAdmitted),
            Script::Lists(vec!["ping"]),
        ]);
        let node = bifrost::Node::new(peer.clone(), bifrost::NoDiscovery);
        let peers = swoosh::peers::Peers::new(&node);
        let ended = ported(&node, &peers, core::time::Duration::ZERO, async |local| {
            client(local).await
        })
        .await;
        assert_eq!(
            format!("{ended:#}"),
            "me/nas does not serve ssh\n  Only nas can add it; on nas, run:\n    swoosh service add ssh"
        );
    }

    /// A later pipe's `NotAdmitted` breaks the run's loop before one of your devices is asked why, so a
    /// host cut while the follow-up waits does not change the line the run ends with.
    #[tokio::test]
    async fn a_later_not_admitted_is_asked_about_after_the_loop_where_no_cut_races_it() {
        use swoosh::testkit::Script;

        // The follow-up's stream gets no answer, so it waits out its bound while the host cuts.
        let peer = nas(vec![
            Script::Holds,
            Script::Refuse(bifrost::Refusal::NotAdmitted),
            Script::Silent,
        ]);
        let node = bifrost::Node::new(peer.clone(), bifrost::NoDiscovery);
        let peers = swoosh::peers::Peers::new(&node);
        let ended = ported(&node, &peers, core::time::Duration::ZERO, async |local| {
            let _refused = tokio::net::TcpStream::connect(local)
                .await
                .expect("connect");
            while peer.dials() < 2 {
                tokio::time::sleep(core::time::Duration::from_millis(10)).await;
            }
            peer.cut();
            core::future::pending::<()>().await;
        })
        .await;
        assert!(ended.is::<crate::commands::machine::Refused>(), "{ended:#}");
        assert_eq!(peer.dials(), 2, "the run's session and one follow-up");
    }

    /// A machine prints as this home's name for its key, else the whole key: a short key is accepted by no
    /// command, so a line that printed one would hand the reader something that does not run.
    #[test]
    fn a_machine_prints_as_its_saved_name_else_its_whole_key() {
        let nas = bifrost::NodeId::from_ed25519_secret(&[3u8; 32]);
        let stranger = bifrost::NodeId::from_ed25519_secret(&[4u8; 32]);
        let mut contacts = Contacts::default();
        contacts
            .save(&"me/nas".parse().expect("a device name"), nas)
            .expect("the name is free");
        assert_eq!(Machine::of(&contacts, nas).to_string(), "me/nas");
        assert_eq!(
            Machine::of(&contacts, stranger).to_string(),
            stranger.to_string(),
            "an unnamed machine prints its whole key"
        );
    }

    /// An upload half that notes whether it was cut, and says when it shut down.
    struct Noted {
        cut: std::rc::Rc<core::cell::Cell<bool>>,
        shut: Option<oneshot::Sender<()>>,
    }
    impl io::AsyncWrite for Noted {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            if let Some(shut) = self.shut.take() {
                let _ = shut.send(());
            }
            Poll::Ready(Ok(()))
        }
    }
    impl super::Upload for Noted {
        fn cut(self) {
            self.cut.set(true);
        }
        /// The word comes on the download half, as through `serve`.
        fn delivered(self) -> impl Future<Output = io::Result<()>> {
            core::future::pending()
        }
    }

    /// A download half over `bytes`, read once `after` fires when one is given, whose landing answers
    /// `landed`.
    struct Landing {
        bytes: &'static [u8],
        landed: Option<io::ErrorKind>,
        after: Option<oneshot::Receiver<()>>,
    }
    impl io::AsyncRead for Landing {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut io::ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if let Some(after) = &mut self.after {
                if Pin::new(after).poll(cx).is_pending() {
                    return Poll::Pending;
                }
                self.after = None;
            }
            Pin::new(&mut self.bytes).poll_read(cx, buf)
        }
    }
    impl super::Download for Landing {
        async fn landed(&mut self) -> io::Result<()> {
            self.landed.map_or(Ok(()), |kind| Err(kind.into()))
        }
    }

    /// An upload half, whether it was cut, and the word it shut down.
    fn noted() -> (
        Noted,
        std::rc::Rc<core::cell::Cell<bool>>,
        Option<oneshot::Receiver<()>>,
    ) {
        let cut = std::rc::Rc::default();
        let (shut, after) = oneshot::channel();
        (
            Noted {
                cut: std::rc::Rc::clone(&cut),
                shut: Some(shut),
            },
            cut,
            Some(after),
        )
    }

    #[tokio::test]
    async fn a_clean_end_exits_0_and_prints_nothing() {
        let (writer, cut, after) = noted();
        let (stdin, input) = mpsc::channel(1);
        stdin.try_send(Ok(b"up".to_vec())).unwrap();
        drop(stdin);
        let reader = Landing {
            bytes: b"down",
            landed: None,
            after,
        };
        let mut output = Vec::new();
        super::pump_stdio(writer, reader, piped(input), &mut output)
            .await
            .unwrap();
        assert_eq!(output, b"down");
        assert!(!cut.get(), "a finished upload is never cut");
    }

    #[tokio::test]
    async fn an_upload_that_did_not_land_exits_1_with_connection_lost() {
        let (writer, _, after) = noted();
        let (stdin, input) = mpsc::channel(1);
        stdin.try_send(Ok(b"up".to_vec())).unwrap();
        drop(stdin);
        let reader = Landing {
            bytes: b"whole download",
            landed: Some(io::ErrorKind::ConnectionReset),
            after,
        };
        let mut output = Vec::new();
        assert_remote(super::pump_stdio(writer, reader, piped(input), &mut output).await);
        // What arrived stays on stdout.
        assert_eq!(output, b"whole download");
    }

    /// `forward ... - < /dev/null` to a service that stopped reading: nothing was sent, so nothing can
    /// have been lost, and no Landed is waited for.
    #[tokio::test]
    async fn an_empty_upload_that_did_not_land_exits_0() {
        let (writer, cut, after) = noted();
        let (stdin, input) = mpsc::channel(1);
        drop(stdin);
        let reader = Landing {
            bytes: b"whole download",
            landed: Some(io::ErrorKind::ConnectionReset),
            after,
        };
        let mut output = Vec::new();
        super::pump_stdio(writer, reader, piped(input), &mut output)
            .await
            .unwrap();
        assert_eq!(output, b"whole download");
        assert!(!cut.get(), "an empty upload still ends cleanly");
    }

    /// The far side holds the upload, and the connection ends as the word arrives: both answers are
    /// ready at once, and the delivery decides, every time.
    #[tokio::test]
    async fn a_delivery_and_a_close_ready_together_exit_0() {
        for _ in 0..32 {
            let (stdin, input) = mpsc::channel(1);
            stdin.try_send(Ok(b"up".to_vec())).unwrap();
            drop(stdin);
            // The download is read only once the upload has ended, so the run reaches its last wait.
            let (writer, after) = after_half_close(());
            let reader = Landing {
                bytes: b"",
                landed: Some(io::ErrorKind::ConnectionAborted),
                after: after.closed,
            };
            super::pump_stdio(Plain(writer), reader, piped(input), io::sink())
                .await
                .expect("a delivered upload exits 0 whatever else is ready");
        }
    }

    #[tokio::test]
    async fn a_terminal_stdin_cuts_the_upload_at_the_downloads_end_and_exits_0() {
        let (writer, cut, _) = noted();
        let (_stdin, input) = mpsc::channel(1);
        let reader = Landing {
            bytes: b"bye",
            // Never asked: the upload did not end, so nothing landed to wait for.
            landed: Some(io::ErrorKind::ConnectionReset),
            after: None,
        };
        super::pump_stdio(writer, reader, terminal(input), io::sink())
            .await
            .unwrap();
        assert!(
            cut.get(),
            "an upload stdin did not end is cut, never ended cleanly"
        );
    }

    #[tokio::test]
    async fn a_stdin_read_error_cuts_the_upload() {
        let (writer, cut, _) = noted();
        let (stdin, input) = mpsc::channel(1);
        stdin.try_send(Err(fault())).unwrap();
        assert_local(
            super::pump_stdio(writer, Plain(PendingReader), piped(input), io::sink())
                .now_or_never()
                .expect("a local stdin error is ready"),
        );
        assert!(cut.get());
    }

    /// The far end of an own-bind pipe over mem, whose peer reads an abort as `ConnectionReset`, and how
    /// its read of the upload ends once the pump has run over `input`, the far end's own reply already
    /// ended when `replied`.
    async fn own_bind_upload_ends(input: super::Stdin, replied: bool) -> io::ErrorKind {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let (session, peer) = sessions().await;
        let (writer, reader) = session.open_bi().await.unwrap();
        let (mut far_write, mut far_read) = peer.accept_bi().await.unwrap();
        if replied {
            far_write.shutdown().await.unwrap();
        }
        let _ = super::pump_stdio(
            super::Stream(writer),
            own_read(reader, &session),
            input,
            io::sink(),
        )
        .await;
        let mut got = Vec::new();
        match far_read.read_to_end(&mut got).await {
            Ok(_) => io::ErrorKind::UnexpectedEof,
            Err(error) => error.kind(),
        }
    }

    #[tokio::test]
    async fn the_own_bind_on_a_terminal_resets_an_upload_its_peer_outlived() {
        // stdin still open when the host's half ends: an interactive session's normal close.
        let (_stdin, input) = mpsc::channel(1);
        assert_eq!(
            own_bind_upload_ends(terminal(input), true).await,
            io::ErrorKind::ConnectionReset
        );
    }

    #[tokio::test]
    async fn the_own_bind_resets_an_upload_whose_stdin_failed() {
        let (stdin, input) = mpsc::channel(1);
        stdin.try_send(Err(fault())).unwrap();
        // The host's reply still open, so only the stdin error can end the run.
        assert_eq!(
            own_bind_upload_ends(piped(input), false).await,
            io::ErrorKind::ConnectionReset
        );
    }

    /// The own bind, its host's half ended first, a piped stdin ending later: the upload runs to its end
    /// and the run exits 0 only once the transport says the far side holds it.
    #[tokio::test]
    async fn the_own_bind_waits_for_delivery_after_its_peer_ended_first() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let (session, peer) = sessions().await;
        let (writer, reader) = session.open_bi().await.unwrap();
        let (mut far_write, mut far_read) = peer.accept_bi().await.unwrap();
        far_write.shutdown().await.unwrap();
        let (stdin, input) = mpsc::channel(1);
        let (output, mut seen) = io::duplex(64);
        let pump = super::pump_stdio(
            super::Stream(writer),
            own_read(reader, &session),
            piped(input),
            Closing(Some(output)),
        );
        tokio::pin!(pump);
        // The download's end reaches stdout's reader while stdin is still open.
        let mut down = Vec::new();
        tokio::time::timeout(GUARD, async {
            tokio::select! {
                _ = &mut pump => panic!("the run ended with stdin open"),
                read = seen.read_to_end(&mut down) => { read.unwrap(); }
            }
        })
        .await
        .expect("stdout's reader saw no end while stdin stayed open");
        stdin.send(Ok(b"up".to_vec())).await.unwrap();
        drop(stdin);
        let mut got = [0; 2];
        tokio::time::timeout(GUARD, async {
            tokio::select! {
                _ = &mut pump => panic!("the run ended before the far side read the upload"),
                read = far_read.read_exact(&mut got) => { read.unwrap(); }
            }
        })
        .await
        .expect("the upload never reached the far side");
        assert!(
            futures::poll!(&mut pump).is_pending(),
            "exit before the far side holds the upload's end"
        );
        let mut rest = Vec::new();
        let ((), result) = tokio::join!(
            async {
                far_read.read_to_end(&mut rest).await.unwrap();
            },
            tokio::time::timeout(GUARD, &mut pump)
        );
        result.expect("delivered once read").unwrap();
        assert_eq!(&got, b"up");
    }

    /// The own bind's download half over `reader`, watching `session`.
    fn own_read(
        reader: bifrost_mem::MemRead,
        session: &bifrost_mem::MemSession,
    ) -> super::OwnRead<'_, bifrost_mem::MemSession> {
        super::OwnRead {
            half: reader,
            session,
        }
    }

    /// The own bind, its host's half ended first and stdin idle: the host closing the session (a revoke
    /// or an expiry) ends the run at once, as cut off.
    #[tokio::test]
    async fn the_own_bind_ends_at_once_when_its_session_closes_while_stdin_idles() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let (session, peer) = sessions().await;
        let (writer, reader) = session.open_bi().await.unwrap();
        let (mut far_write, _far_read) = peer.accept_bi().await.unwrap();
        far_write.shutdown().await.unwrap();
        let (_stdin, input) = mpsc::channel(1);
        let (output, mut seen) = io::duplex(64);
        let pump = super::pump_stdio(
            super::Stream(writer),
            own_read(reader, &session),
            piped(input),
            Closing(Some(output)),
        );
        tokio::pin!(pump);
        let mut down = Vec::new();
        tokio::time::timeout(GUARD, async {
            tokio::select! {
                _ = &mut pump => panic!("the run ended with stdin open"),
                read = seen.read_to_end(&mut down) => { read.unwrap(); }
            }
        })
        .await
        .expect("stdout's reader saw no end while stdin stayed open");
        assert!(futures::poll!(&mut pump).is_pending(), "stdin still idles");
        peer.close();
        assert_remote(
            tokio::time::timeout(GUARD, pump)
                .await
                .expect("the closed session ended the run though stdin idles"),
        );
    }

    /// The own bind, its upload ended cleanly: a far side that stops reading before it holds the
    /// upload's end fails the transport's delivery, and the run exits as cut off.
    #[tokio::test]
    async fn the_own_bind_exits_cut_off_when_delivery_fails() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let (session, peer) = sessions().await;
        let (writer, reader) = session.open_bi().await.unwrap();
        let (mut far_write, mut far_read) = peer.accept_bi().await.unwrap();
        far_write.shutdown().await.unwrap();
        let (stdin, input) = mpsc::channel(1);
        stdin.send(Ok(b"up".to_vec())).await.unwrap();
        drop(stdin);
        let pump = super::pump_stdio(
            super::Stream(writer),
            own_read(reader, &session),
            piped(input),
            io::sink(),
        );
        tokio::pin!(pump);
        // The far side reads the bytes, so the writes and the clean end all succeed, and stops
        // before it reads the end: only the delivery can fail.
        let mut got = [0; 2];
        tokio::time::timeout(GUARD, async {
            tokio::select! {
                _ = &mut pump => panic!("the run ended before the far side read the upload"),
                read = far_read.read_exact(&mut got) => { read.unwrap(); }
            }
        })
        .await
        .expect("the upload never reached the far side");
        assert_eq!(&got, b"up");
        assert!(
            futures::poll!(&mut pump).is_pending(),
            "no exit before delivery"
        );
        drop(far_read);
        assert_remote(
            tokio::time::timeout(GUARD, pump)
                .await
                .expect("the failed delivery ended the run"),
        );
        drop(peer);
    }

    /// How long a row waits for what should happen at once.
    const GUARD: core::time::Duration = core::time::Duration::from_secs(1);

    /// An output whose close drops its writer, so the reader sees its end.
    struct Closing(Option<io::DuplexStream>);
    impl io::AsyncWrite for Closing {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            match &mut self.0 {
                Some(out) => Pin::new(out).poll_write(cx, buf),
                None => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            }
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            match &mut self.0 {
                Some(out) => Pin::new(out).poll_flush(cx),
                None => Poll::Ready(Ok(())),
            }
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            panic!("the local stdout is closed, never shut down")
        }
    }
    impl super::Output for Closing {
        fn close(&mut self) -> io::Result<()> {
            self.0 = None;
            Ok(())
        }
    }

    /// A download half as through `serve`: `bytes` and their end, then the word that the upload landed
    /// once `verdict` fires; a dropped `verdict` is the resident closing without it.
    struct Resident {
        bytes: &'static [u8],
        verdict: oneshot::Receiver<()>,
    }
    impl io::AsyncRead for Resident {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut io::ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.bytes).poll_read(cx, buf)
        }
    }
    impl super::Download for Resident {
        async fn landed(&mut self) -> io::Result<()> {
            (&mut self.verdict)
                .await
                .map_err(|_| io::ErrorKind::ConnectionReset.into())
        }
    }

    /// A piped run whose download ends first through `serve`, its stdout read by a reader: the pump, its
    /// stdin, the verdict to fire, whether the upload was cut, the word it shut down, and the reader.
    #[allow(clippy::type_complexity)]
    fn download_first() -> (
        impl Future<Output = eyre::Result<()>>,
        mpsc::Sender<io::Result<Vec<u8>>>,
        oneshot::Sender<()>,
        std::rc::Rc<core::cell::Cell<bool>>,
        oneshot::Receiver<()>,
        io::DuplexStream,
    ) {
        let (writer, cut, shut) = noted();
        let shut = shut.unwrap();
        let (stdin, input) = mpsc::channel(1);
        let (verdict, waiting) = oneshot::channel();
        let (output, seen) = io::duplex(64);
        let reader = Resident {
            bytes: b"down",
            verdict: waiting,
        };
        let pump = super::pump_stdio(writer, reader, piped(input), Closing(Some(output)));
        (pump, stdin, verdict, cut, shut, seen)
    }

    #[tokio::test]
    async fn a_download_ending_first_closes_stdout_at_once_while_stdin_stays_open() {
        use tokio::io::AsyncReadExt as _;

        let (pump, stdin, _verdict, cut, _, mut seen) = download_first();
        tokio::pin!(pump);
        let mut down = Vec::new();
        tokio::time::timeout(GUARD, async {
            tokio::select! {
                _ = &mut pump => panic!("the run ended with stdin open"),
                read = seen.read_to_end(&mut down) => { read.unwrap(); }
            }
        })
        .await
        .expect("stdout's reader saw no end while stdin stayed open");
        assert_eq!(down, b"down");
        assert!(!stdin.is_closed(), "stdin is still being read");
        assert!(futures::poll!(&mut pump).is_pending());
        assert!(!cut.get(), "the upload goes on");
    }

    #[tokio::test]
    async fn a_download_ending_first_then_stdin_ending_exits_0_only_on_landed() {
        let (pump, stdin, verdict, cut, shut, _seen) = download_first();
        tokio::pin!(pump);
        stdin.send(Ok(b"up".to_vec())).await.unwrap();
        drop(stdin);
        tokio::select! {
            _ = &mut pump => panic!("the run ended before Landed"),
            ended = shut => ended.unwrap(),
        }
        assert!(
            futures::poll!(&mut pump).is_pending(),
            "no exit before Landed"
        );
        verdict.send(()).unwrap();
        tokio::time::timeout(GUARD, pump)
            .await
            .expect("Landed ends the run")
            .unwrap();
        assert!(!cut.get(), "a finished upload is never cut");
    }

    #[tokio::test]
    async fn a_download_ending_first_with_no_landed_exits_cut_off() {
        let (pump, stdin, verdict, _, shut, _seen) = download_first();
        tokio::pin!(pump);
        stdin.send(Ok(b"up".to_vec())).await.unwrap();
        drop(stdin);
        tokio::select! {
            _ = &mut pump => panic!("the run ended before the resident answered"),
            ended = shut => ended.unwrap(),
        }
        drop(verdict);
        assert_remote(
            tokio::time::timeout(GUARD, pump)
                .await
                .expect("a close without Landed ends the run"),
        );
    }

    #[tokio::test]
    async fn a_resident_close_after_the_downloads_end_ends_a_run_with_idle_stdin_at_once() {
        let (pump, _stdin, verdict, cut, _, _seen) = download_first();
        drop(verdict);
        assert_remote(
            tokio::time::timeout(GUARD, pump)
                .await
                .expect("the close ended the run though stdin idles"),
        );
        assert!(cut.get(), "an upload stdin did not end is cut");
    }

    /// The descriptor stdout is closed through: its reader sees the end at once, while the number
    /// still names something a write succeeds on.
    #[test]
    fn closing_a_descriptor_onto_null_ends_its_pipe_and_keeps_the_number() {
        use std::io::{Read as _, Write as _};
        use std::os::fd::AsFd as _;

        let (mut reader, mut writer) = std::io::pipe().unwrap();
        writer.write_all(b"down").unwrap();
        super::close_onto_null(writer.as_fd()).unwrap();
        let mut got = Vec::new();
        reader.read_to_end(&mut got).unwrap();
        assert_eq!(got, b"down");
        writer.write_all(b"after").unwrap();
    }

    /// A socket whose reader has already gone has its end already: closing it is no error.
    #[test]
    fn closing_a_socket_whose_reader_has_gone_onto_null_succeeds() {
        use std::os::fd::AsFd as _;

        let (reader, writer) = std::os::unix::net::UnixStream::pair().unwrap();
        drop(reader);
        super::close_onto_null(writer.as_fd()).unwrap();
    }

    /// A socket that another descriptor also names, as when a host hands one socket over as both
    /// stdin and stdout: closing stdout still ends it for its reader at once.
    #[test]
    fn closing_a_shared_socket_onto_null_ends_it_for_its_reader() {
        use std::io::{Read as _, Write as _};
        use std::os::fd::AsFd as _;

        let (mut reader, mut writer) = std::os::unix::net::UnixStream::pair().unwrap();
        let _stdin = writer.try_clone().unwrap();
        reader
            .set_read_timeout(Some(core::time::Duration::from_secs(1)))
            .unwrap();
        writer.write_all(b"down").unwrap();
        super::close_onto_null(writer.as_fd()).unwrap();
        let mut got = Vec::new();
        reader
            .read_to_end(&mut got)
            .expect("the reader saw no end while another descriptor named the socket");
        assert_eq!(got, b"down");
    }
}
