//! The one swoosh connect runner, and the [`To`] sink selector it is parameterized by.
//!
//! NOT a verb: `swoosh forward <peer> <service> <port | unix:<path> | ->` is the surface, and this is
//! the body it drives. The two halves are split because the act ("dial a peer's served service,
//! optionally presenting a cap, then drive it") is one thing while WHERE the bytes go is a choice the
//! caller makes: `Port` binds a local port and forwards each connection, `Stdout` streams the single
//! stream over this process's stdin/stdout ([`pump_stdio`], which `forward`'s bridge drives over a stream
//! from either path's source), `UnixListener` is reserved. The present/badge choice lives in exactly one
//! place (the caller picks `present` before handing off).
//!
//! `swoosh ssh` reaches the same runner the same way, through the PUBLIC verb: its `ProxyCommand`
//! re-invokes THIS binary as `<self> forward <peer> <service> -` via `current_exe()` (not a separate
//! `tightbeam` binary on PATH), so the bridge an operator debugs by hand is the one ssh runs.
//!
//! The stdout sink ends when the connection its stream rides ends (on a revoke or an expiry), whatever
//! the local side is doing, on both paths: [`pump_stdio`] says how, including
//! that a stdin that is not a terminal still finishes its upload after a clean end. A port's [`Listener`]
//! stays up across a dropped connection on both paths: the pipes riding it end, and the next pipe's open
//! redials. It ends when a pipe's open says every later one would fail the same way (the machine's
//! `NotAdmitted`, an ended standing, `serve` gone), or `serve` is confirmed stalled. Any other pipe's
//! failure keeps the port listening, with one [`PipeFailures`] warning per run of them. tightbeam's own
//! stdio bridge and port forward end neither way yet: the bridge waits on a stdin read before the
//! process can exit, and the forward keeps listening on a session that is gone. So the exchange, the
//! bridge and the forward live here, over tightbeam's wire frames, until tightbeam's own end the same
//! way.

use core::cell::{Cell, RefCell};
use core::future::Future;
use core::ops::ControlFlow;
use core::pin::Pin;
use core::str::FromStr;
use core::task::{Context, Poll};
use core::time::Duration;
use std::io::{IsTerminal as _, Read as _};
use std::path::PathBuf;

use bifrost::{NodeId, Refusal, Session, WriteEnd};
use futures::StreamExt as _;
use futures::stream::FuturesUnordered;
use swoosh::contacts::Contacts;
use swoosh::escape::{Escaped, escaped_report};
use swoosh::peer::Machine as PeerMachine;
use swoosh::peers::{OpenError, SessionEnd};
use swoosh::serve::control_codec::OpenRefusal;
use swoosh::streams::{Ask, Opened, StreamSource, Unopened};
use tokio::io::{self, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use crate::commands::machine;
use crate::commands::route::{Pipe, Route};

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

/// A listener's streams, on either path: one admission, then one stream per local connection, each from
/// `source` as `ask` asks, each outcome worded by `route`. A connection that ends under a live pipe ends
/// that pipe alone, so a listener stays up across a dropped connection, and the next pipe's open redials;
/// the run ends only when an open says every later one would fail the same way.
pub struct Listener<'a, S> {
    /// Where each stream comes from: the run's own bind, or `serve`.
    pub source: &'a S,
    /// The one stream every pipe asks for, admission included.
    pub ask: &'a Ask,
    /// The path, for the line each outcome prints.
    pub route: &'a Route<'a>,
    /// The machine as typed, for the lines that name it.
    pub machine: &'a PeerMachine,
}

/// Why a listener's loop stopped, before its line is worded.
pub enum Over {
    /// A pipe's open met an outcome every later one would repeat: worded by [`Route::ending`] once the
    /// loop has stopped, so the one question it may ask races no pipe.
    Ends(Unopened),
    /// The run ends with this line: `serve` confirmed stalled, or gone under a pipe.
    Line(eyre::Report),
}

impl<S: StreamSource> Listener<'_, S> {
    /// Prove the gate admits the ask before any start line prints, so a refusal is one line and a
    /// non-zero exit rather than a listener that refuses every connection. The stream is ended with End,
    /// so the far side reads a clean end of an empty upload, never a reset.
    pub async fn admit(&self) -> eyre::Result<()> {
        let mut opened = match self.source.open(self.ask).await {
            Ok(opened) => opened,
            Err(unopened) => return Err(self.ending(Over::Ends(unopened)).await),
        };
        match opened.write.shutdown().await {
            Ok(()) => Ok(()),
            Err(error) => Err(self.route.cut_or(escaped_report(error.into())).await),
        }
    }

    /// One pipe's stream, `None` when its open failed for that pipe alone (told to `failures`), or why
    /// the run is over.
    pub async fn open(
        &self,
        failures: &PipeFailures<impl std::io::Write>,
    ) -> Result<Option<Opened<S::Write, S::Read>>, Over> {
        let unopened = match self.source.open(self.ask).await {
            Ok(opened) => {
                failures.carried();
                return Ok(Some(opened));
            }
            Err(unopened) => unopened,
        };
        match self.route.pipe(unopened, self.machine).await {
            Pipe::Ends(unopened) => Err(Over::Ends(unopened)),
            Pipe::Stalled(line) => Err(Over::Line(line)),
            Pipe::Failed(failure, line) => {
                failures.failed(failure, &line);
                Ok(None)
            }
        }
    }

    /// The line the run ends with for `over`.
    pub async fn ending(&self, over: Over) -> eyre::Report {
        match over {
            Over::Ends(unopened) => {
                self.route
                    .ending(unopened, self.source, self.ask, self.machine)
                    .await
            }
            Over::Line(line) => line,
        }
    }

    /// Carry each connection `local` accepts over its own stream, at most [`MAX_PIPES`] at once, until a
    /// pipe ends the run: the line it ends with. A pipe that opened is carried whatever ends it, and its
    /// break goes to the log, unless `serve` went under it: asked then, so the run ends at once rather
    /// than at the next connection's open.
    pub async fn forward(
        &self,
        local: TcpListener,
        failures: &PipeFailures<impl std::io::Write>,
    ) -> eyre::Report
    where
        S::Read: Download,
    {
        let over = accept_each(local, MAX_PIPES, |tcp| async move {
            let opened = match self.open(failures).await {
                Ok(Some(opened)) => opened,
                Ok(None) => return ControlFlow::Continue(()),
                Err(over) => return ControlFlow::Break(over),
            };
            if let Err(error) = splice(tcp, opened).await {
                if let Some(stopped) = self.route.stopped().await {
                    return ControlFlow::Break(Over::Line(stopped));
                }
                tracing::warn!("connection failed: {:#}", escaped_report(error));
            }
            ControlFlow::Continue(())
        })
        .await;
        self.ending(over).await
    }
}

/// Carry `tcp` over `opened` both ways until both ends close. An upload that carried a byte is whole
/// only once the far side holds it: the upload half's `delivered` by own bind, the download half's
/// Landed through `serve`, whichever comes, with no clock of its own. A far side that stops answering
/// ends the stream when its transport gives up on it.
pub async fn splice<W, R>(mut tcp: TcpStream, opened: Opened<W, R>) -> eyre::Result<()>
where
    W: io::AsyncWrite + WriteEnd + Unpin,
    R: Download,
{
    let Opened {
        mut write,
        mut read,
        ..
    } = opened;
    let (up, _down) =
        io::copy_bidirectional(&mut tcp, &mut io::join(&mut read, &mut write)).await?;
    if up > 0 {
        tokio::select! {
            // Delivery first: a far side that holds the upload and then closes has it whole.
            biased;
            delivered = WriteEnd::delivered(write) => delivered?,
            landed = read.landed() => landed?,
        }
    }
    Ok(())
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

/// The most local connections one forward or proxy holds at once, carried or waiting for a stream.
/// Below the Bulk streams one machine takes from a run or from `serve`
/// ([`BULK_STREAMS`](swoosh::peers::BULK_STREAMS)), so one listener that anyone on this computer can fill
/// still leaves that machine's other fan-outs room; below the streams one iroh session carries (at least
/// 224); and far enough below a default descriptor limit (256 on macOS) that connections waiting for a
/// stream cannot exhaust the process. Past it, new connections wait in the kernel's listen backlog.
pub const MAX_PIPES: usize = 96;

// One listener filled to its cap must leave its machine's Bulk lane places for the run's other fan-outs,
// by own bind and through `serve`, whose Bulk cap is the same: anyone on this computer can fill a port.
const _: () = assert!(MAX_PIPES < swoosh::peers::BULK_STREAMS as usize);

/// How long a local listener waits before accepting again after an accept fails. An error such as running
/// out of descriptors repeats on every attempt until something frees, so retrying at once would spin.
pub const ACCEPT_RETRY: Duration = Duration::from_millis(100);

/// Accept each local connection and hand it to `carry`, all carried concurrently, until one of them
/// breaks the run: what it broke with is what this returns.
///
/// At most `cap` are held at once ([`MAX_PIPES`] in a run; past it, new connections wait in the kernel's
/// backlog), and a failed accept pauses for [`ACCEPT_RETRY`] rather than spinning. One failed accept or
/// pipe never tears down the ones in flight: a pipe logs its own failure and continues the run.
pub async fn accept_each<F, Fut, B>(listener: TcpListener, cap: usize, mut carry: F) -> B
where
    F: FnMut(TcpStream) -> Fut,
    Fut: Future<Output = ControlFlow<B>>,
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
                if let ControlFlow::Break(broke) = flow {
                    return broke;
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

/// What a listener tells the person of its pipes' failures: one `warning:` for the first pipe whose Open
/// fails after one carried, or after the start, then nothing until a pipe carries again, so a machine
/// that went away prints one line rather than one per connection. Every failure still goes to the log.
///
/// A pipe carries once its stream opens, whatever ends it after. The line is written to `err`, stderr in
/// a run, and a failed write is not the run's failure.
pub struct PipeFailures<W> {
    /// The machine as the line leads with it ([`machine::named`]).
    machine: String,
    since: Cell<Since>,
    // A cell, as every pipe of a run is polled on its one task and none holds the borrow across an await.
    err: RefCell<W>,
}

/// What happened since a listener last warned.
#[derive(Clone, Copy)]
enum Since {
    /// A pipe carried, or the run just started: the next failure warns.
    Carried,
    /// The warning is out, and no pipe has carried since.
    Warned,
}

impl<W: std::io::Write> PipeFailures<W> {
    /// A run's warnings for the pipes to `machine`, written to `err`.
    pub fn new(machine: &PeerMachine, err: W) -> Self {
        Self {
            machine: machine::named(machine),
            since: Cell::new(Since::Carried),
            err: RefCell::new(err),
        }
    }

    /// A pipe's stream opened: the next failure warns again.
    pub fn carried(&self) {
        self.since.set(Since::Carried);
    }

    /// A pipe's Open failed and the run listens on: `error`, its peer text already escaped, goes to the
    /// log, and `failure` into the warning when this is the first failure since a pipe carried. A
    /// failure the warning has no words for (`None`) goes to the log alone.
    pub fn failed(&self, failure: Option<Failure>, error: &eyre::Report) {
        tracing::warn!("connection failed: {error:#}");
        let Some(failure) = failure else {
            return;
        };
        if let Since::Warned = self.since.replace(Since::Warned) {
            return;
        }
        let _ = writeln!(
            self.err.borrow_mut(),
            "warning: a connection to {} failed: {failure}\n  Still listening for new connections.",
            self.machine
        );
    }
}

/// Why a pipe's Open failed, as its warning says it: one clause per kind of failure, the same on both
/// paths, with the machine's text escaped as it is built.
pub enum Failure {
    /// The machine answered and refused (`Unavailable`, `BadRequest`, or a kind this build cannot name):
    /// the refusal as the wire words it, escaped.
    Refused(String),
    /// No session reached the machine, or the dial or the Open ran out of time.
    Unreachable,
    /// The stream broke while it opened: with the wire's escaped detail through `serve`, and none by own
    /// bind, where the cause can carry the host's reason for a cut.
    Interrupted(Option<String>),
    /// The lane, or `serve`, holds as many streams as it takes, here on this machine.
    Busy,
}

impl Failure {
    /// The clause for a listener pipe whose open gave no stream, the same row for the same outcome on
    /// either path. `None` for an outcome that ends the run, which never warns.
    pub fn of(unopened: &Unopened) -> Option<Self> {
        if unopened.ends_run() {
            return None;
        }
        Some(match unopened {
            Unopened::Refused(OpenRefusal::Peer(refusal)) => {
                Self::refused(&Refusal::from(refusal.clone()))
            }
            Unopened::Refused(OpenRefusal::Unreachable(_) | OpenRefusal::Timeout)
            | Unopened::Own(OpenError::Unreachable(_) | OpenError::Timeout) => Self::Unreachable,
            Unopened::Refused(OpenRefusal::Broken(detail)) => {
                Self::Interrupted(Some(Escaped(detail.as_str()).to_string()))
            }
            Unopened::Refused(OpenRefusal::Busy) | Unopened::Own(OpenError::Busy) => Self::Busy,
            // A refusal this build cannot read, a stream that failed to open, a home that could not be
            // read, the resident's error reply, a control connection that failed before its reply: the
            // reason is the log's. The rows that end the run returned above.
            Unopened::Refused(
                OpenRefusal::PeerUnreadable(_) | OpenRefusal::StandingEnded | OpenRefusal::NotHere,
            )
            | Unopened::Own(OpenError::Open(_))
            | Unopened::Home(_)
            | Unopened::ServeError(_)
            | Unopened::ServeGone
            | Unopened::Skew
            | Unopened::Malformed(_)
            | Unopened::Control(_) => Self::Interrupted(None),
        })
    }

    /// The machine's `refusal`.
    pub fn refused(refusal: &Refusal) -> Self {
        Self::Refused(Escaped(&refusal.to_string()).to_string())
    }

    /// An own-bind Open's `error`: a refusal by its kind, and a stream that failed to open interrupted.
    pub fn of_open(error: &OpenError) -> Self {
        match error {
            OpenError::Busy => Self::Busy,
            OpenError::Timeout | OpenError::Unreachable(_) => Self::Unreachable,
            OpenError::Open(bifrost::Error::Refused(refusal)) => Self::refused(refusal),
            OpenError::Open(_) => Self::Interrupted(None),
        }
    }
}

impl core::fmt::Display for Failure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Refused(refusal) => write!(f, "reached, but refused ({refusal})"),
            Self::Unreachable => f.write_str("unreachable"),
            Self::Interrupted(Some(detail)) => write!(f, "interrupted ({detail})"),
            Self::Interrupted(None) => f.write_str("interrupted"),
            Self::Busy => f.write_str("too many connections here"),
        }
    }
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

/// This process's stdin and stdout, for a bridge to open once its stream is admitted: a refused one
/// never starts the thread that reads stdin.
pub(crate) fn stdio() -> eyre::Result<(Stdin, Stdout)> {
    Ok((Stdin::open()?, Stdout::default()))
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

// The word that the upload landed comes on the upload half, so this only fails, once the connection
// the half rides closes: the host cut it (on a revoke or an expiry), or the path to it failed.
impl<R: io::AsyncRead + Unpin, S: Session> Download for swoosh::peers::Half<R, S> {
    async fn landed(&mut self) -> io::Result<()> {
        self.closed().await;
        Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "session closed",
        ))
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
pub(crate) mod tests {
    use core::future::Future as _;
    use core::pin::Pin;
    use core::task::{Context, Poll};

    use bifrost::{Session as _, Transport as _};
    use futures::FutureExt as _;
    use swoosh::contacts::Contacts;
    use swoosh::testkit::HostilePeer;
    use tokio::io;
    use tokio::sync::{mpsc, oneshot};

    use super::{Machine, To};

    /// A gate's refusal detail holding a carriage return, an ESC CSI sequence and a bidi override.
    const HOSTILE: &str = "no\r\u{1b}[2Kforwarding 127.0.0.1:1 to x\u{202e}";
    /// [`HOSTILE`] as it prints.
    const ESCAPED: &str = r"no\r\u{1b}[2Kforwarding 127.0.0.1:1 to x\u{202e}";

    #[test]
    fn a_cut_has_no_printable_source() {
        let report = eyre::Report::new(super::ConnectionLost);
        assert_eq!(report.chain().count(), 1);
        assert_eq!(format!("error: {report:#}\n"), "error: connection lost\n");
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

    /// Reach a peer whose gate refuses with [`HOSTILE`], forwarding a port, or bridging stdout when
    /// `port` is `None`.
    async fn refused(port: Option<u16>) -> eyre::Report {
        failed(HostilePeer::RefusesAtTheGate(HOSTILE), port).await
    }

    /// `forward <host> db <port | ->` by own bind, from a home holding nothing: the error it fails with,
    /// before a port is bound or stdin is opened.
    async fn failed(host: HostilePeer, port: Option<u16>) -> eyre::Report {
        use clap::Parser as _;

        let node = bifrost::Node::new(host, bifrost::NoDiscovery);
        let peers = swoosh::peers::Peers::new(&node);
        let key = HostilePeer::node_id().to_string();
        let to = port.map_or_else(|| "-".to_owned(), |port| port.to_string());
        let Some(crate::Command::Forward(cmd)) =
            crate::Cli::try_parse_from(["swoosh", "forward", key.as_str(), "db", to.as_str()])
                .expect("a forward parses")
                .command
        else {
            panic!("a `forward`");
        };
        let contacts = Contacts::default();
        let machine = cmd.peer.machine(&contacts).expect("a key is one machine");
        let home = crate::commands::through_serve::tests::empty_home("hostile-forward");
        let bound = crate::probe_route_tests::bound();
        let route = crate::commands::route::Route::Own {
            peer: &cmd.peer,
            bound: &bound,
            this: node.node_id(),
        };
        let credential = swoosh::credential::Credential::dialing(&cmd.peer, "db");
        let source = swoosh::streams::OwnBind::new(&peers, &home, node.node_id(), &credential);
        cmd.forward(
            source,
            &route,
            &machine,
            &contacts,
            || -> eyre::Result<(super::Stdin, io::Sink)> {
                panic!("stdin is opened only once the stream is admitted")
            },
        )
        .await
        .expect_err("a refused reach is an error")
    }

    // A forward whose gate refuses prints the refusal, and its detail is the peer's text: escaped, on one
    // line, so it cannot erase the error and draw a `forwarding` line in its place. The port prints the
    // bridge's line.
    #[tokio::test]
    async fn a_hostile_forward_refusal_prints_escaped() {
        let error = refused(Some(1)).await;
        assert_eq!(
            format!("{error:#}"),
            format!("stream refused: unavailable: {ESCAPED}")
        );
    }

    // The stdio bridge (`-`, and `swoosh ssh`'s ProxyCommand through it) prints the same refusal the
    // same way.
    #[tokio::test]
    async fn a_hostile_stdio_refusal_prints_escaped() {
        let error = refused(None).await;
        assert_eq!(
            format!("{error:#}"),
            format!("stream refused: unavailable: {ESCAPED}")
        );
    }

    // A host that ends the stream before it answers (it died mid-dial) prints the exchange's own cause, on
    // either sink as a stream broken while it opened, as through `serve`.
    #[tokio::test]
    async fn a_host_that_hangs_up_before_answering_prints_the_cause() {
        for port in [Some(1), None] {
            let error = failed(HostilePeer::HangsUp, port).await;
            assert_eq!(
                format!("{error:#}"),
                "stream: early eof",
                "reaching to {port:?}"
            );
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

    /// `forward <typed> ssh 1`, as `forward` parses it.
    pub(crate) fn port_forward(typed: &str) -> crate::commands::forward::ForwardCmd {
        use clap::Parser as _;

        let Some(crate::Command::Forward(cmd)) =
            crate::Cli::try_parse_from(["swoosh", "forward", typed, "ssh", "1"])
                .expect("a forward parses")
                .command
        else {
            panic!("a `forward`");
        };
        cmd
    }

    /// A forward to `typed` by own bind, resolved against a book holding your device `me/nas` and bob's
    /// `bob/nas`, both at the scripted peer's key in turn, whose gate answers `script`.
    async fn forwarded(
        typed: &str,
        script: Vec<swoosh::testkit::Script>,
    ) -> (eyre::Report, swoosh::testkit::ScriptedPeer) {
        let key = bifrost::NodeId::from_ed25519_secret(&[0x66; 32]);
        let mut contacts = Contacts::default();
        contacts
            .save(&typed.parse().expect("a machine name"), key)
            .expect("the name is free");
        let cmd = port_forward(typed);
        let machine = cmd.peer.machine(&contacts).expect("one machine");
        let peer = swoosh::testkit::ScriptedPeer::new(key, script);
        let node = bifrost::Node::new(peer.clone(), bifrost::NoDiscovery);
        let peers = swoosh::peers::Peers::new(&node);
        // Tagged without the `/`, which would nest the home's directory.
        let home = crate::commands::through_serve::tests::empty_home(&typed.replace('/', "-"));
        let bound = crate::probe_route_tests::bound();
        let route = crate::commands::route::Route::Own {
            peer: &cmd.peer,
            bound: &bound,
            this: node.node_id(),
        };
        let credential = swoosh::credential::Credential::Family { present: None };
        let source = swoosh::streams::OwnBind::new(&peers, &home, node.node_id(), &credential);
        let error = cmd
            .listen(source, &route, &machine, &contacts, 1)
            .await
            .expect_err("a refused forward is an error");
        (error, peer)
    }

    // A forward refused by one of your devices asks it why, over the run's Main session, and says what it
    // found: here the device's list lacks the service, so the line names the form that adds it there.
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
            "the follow-up asks on Main, beside the port's Bulk session"
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

    /// `forward <port>` by own bind for `me/nas`'s `ssh`, on `node` and its run's `peers`, presenting
    /// from `home`: admitted on one stream, then listening while `clients` connect, with the owner's sweep
    /// driven beside it as a run drives it. Returns the line the run ended with, `None` when `clients`
    /// finished with the port still listening, and what the run wrote to stderr.
    pub(crate) async fn ported<'n>(
        node: &'n bifrost::Node<swoosh::testkit::ScriptedPeer, bifrost::NoDiscovery>,
        peers: &swoosh::peers::Peers<'n, swoosh::testkit::ScriptedPeer, bifrost::NoDiscovery>,
        home: &swoosh::home::Home,
        clients: impl AsyncFnOnce(core::net::SocketAddr),
    ) -> (Option<eyre::Report>, String) {
        let contacts = crate::commands::through_serve::tests::book();
        let machine = crate::commands::through_serve::tests::machine(&contacts, "me/nas");
        let cmd = port_forward("me/nas");
        let bound = crate::probe_route_tests::bound();
        let route = crate::commands::route::Route::Own {
            peer: &cmd.peer,
            bound: &bound,
            this: node.node_id(),
        };
        let credential = swoosh::credential::Credential::Family { present: None };
        let source = swoosh::streams::OwnBind::new(peers, home, node.node_id(), &credential);
        let ask = listening(&machine);
        let listener = super::Listener {
            source: &source,
            ask: &ask,
            route: &route,
            machine: &machine,
        };
        listener.admit().await.expect("admitted");
        let local = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("a free port");
        let at = local.local_addr().expect("its address");
        let mut err = Vec::new();
        let ended = {
            let failures = super::PipeFailures::new(&machine, &mut err);
            tokio::time::timeout(crate::commands::through_serve::tests::ROW_BOUND, async {
                tokio::select! {
                    // The run's end first: a client that saw its pipe end may finish in the same poll.
                    biased;
                    ended = listener.forward(local, &failures) => Some(ended),
                    never = peers.sweep() => match never {},
                    () = clients(at) => None,
                }
            })
            .await
            .expect("the run ended, or its clients finished")
        };
        (ended, String::from_utf8(err).expect("utf-8"))
    }

    /// The stream a port to `machine`'s `ssh` asks for: Bulk, presenting no link.
    pub(crate) fn listening(machine: &swoosh::peer::Machine) -> swoosh::streams::Ask {
        swoosh::streams::Ask {
            peer: machine.key(),
            hints: swoosh::peers::Hints::NONE,
            service: "ssh".parse().expect("a service"),
            lane: swoosh::serve::control_codec::OpenLane::Bulk,
            slip: None,
        }
    }

    /// A peer at `me/nas`'s key whose gate answers `script`.
    pub(crate) fn nas(script: Vec<swoosh::testkit::Script>) -> swoosh::testkit::ScriptedPeer {
        let contacts = crate::commands::through_serve::tests::book();
        let key = crate::commands::through_serve::tests::machine(&contacts, "me/nas").key();
        swoosh::testkit::ScriptedPeer::new(key, script)
    }

    /// One local client that uploads nothing, closes its upload and reads to the end.
    pub(crate) async fn client(local: core::net::SocketAddr) {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let mut client = tokio::net::TcpStream::connect(local)
            .await
            .expect("connect");
        let _ = client.shutdown().await;
        let _ = client.read_to_end(&mut Vec::new()).await;
    }

    /// A home holding nothing, for a row whose streams present nothing.
    fn bare(tag: &str) -> swoosh::home::Home {
        crate::commands::through_serve::tests::empty_home(&format!("port-{tag}"))
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
        let (ended, err) = ported(&node, &peers, &bare("bulk"), async |local| {
            client(local).await;
        })
        .await;
        assert!(ended.is_none(), "still listening: {ended:?}");
        assert_eq!(err, "", "the pipe carried");
        assert_eq!(peer.dials(), 2, "one session per lane");
    }

    /// A later pipe's `NotAdmitted` ends a port by own bind with the dial refusal, one of your devices
    /// asked why, as the admission's refusal would, and with no warning first.
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
        let (ended, err) = ported(&node, &peers, &bare("not-admitted"), async |local| {
            client(local).await;
            core::future::pending().await
        })
        .await;
        assert_eq!(
            ended.map(|ended| format!("{ended:#}")).as_deref(),
            Some(
                "me/nas does not serve ssh\n  Only nas can add it; on nas, run:\n    swoosh service add ssh"
            )
        );
        assert_eq!(err, "");
    }

    /// By own bind the first pipe to fail after the start warns, by its kind, the failures after it do
    /// not, and a pipe whose stream opened is carried whatever ends it: one whose stream broke under its
    /// upload warns nothing, and the next pipe refused warns again.
    #[tokio::test]
    async fn a_port_by_own_bind_warns_once_per_run_of_failed_pipes() {
        use swoosh::testkit::Script;
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let down = || {
            Script::Refuse(bifrost::Refusal::Unavailable {
                detail: bifrost::RefusalDetail::bounded("down"),
            })
        };
        // The fourth pipe's gate admits it, sends an empty list and lets go of its stream.
        let peer = nas(vec![
            Script::Holds,
            down(),
            down(),
            Script::Lists(vec![]),
            down(),
        ]);
        let node = bifrost::Node::new(peer.clone(), bifrost::NoDiscovery);
        let peers = swoosh::peers::Peers::new(&node);
        let (ended, err) = ported(&node, &peers, &bare("warn"), async |local| {
            client(local).await;
            client(local).await;
            let mut broken = tokio::net::TcpStream::connect(local)
                .await
                .expect("connect");
            let mut list = [0; 4];
            broken.read_exact(&mut list).await.expect("the list");
            // Room for the gate to let go, so the upload below meets a stream nobody reads.
            tokio::time::sleep(core::time::Duration::from_millis(50)).await;
            let _ = broken.write_all(b"ping").await;
            let _ = broken.shutdown().await;
            let _ = broken.read_to_end(&mut Vec::new()).await;
            client(local).await;
        })
        .await;
        assert!(ended.is_none(), "still listening: {ended:?}");
        let down = crate::commands::through_serve::tests::warning(
            "reached, but refused (unavailable: down)",
        );
        assert_eq!(err, format!("{down}{down}"));
    }

    /// A local client that resets its connection once its stream opened warns nothing: the pipe carried,
    /// and the copy's failure, the client's own act, goes to the log alone.
    #[tokio::test]
    async fn a_local_client_reset_after_its_stream_opened_warns_nothing() {
        use swoosh::testkit::Script;
        use tokio::io::AsyncWriteExt as _;

        let peer = nas(vec![Script::Holds, Script::ReadsThenHolds]);
        let node = bifrost::Node::new(peer.clone(), bifrost::NoDiscovery);
        let peers = swoosh::peers::Peers::new(&node);
        let (ended, err) = ported(&node, &peers, &bare("reset"), async |local| {
            let mut reset = tokio::net::TcpStream::connect(local)
                .await
                .expect("connect");
            reset.write_all(b"ping").await.expect("the upload");
            while peer.received() != b"ping" {
                tokio::time::sleep(core::time::Duration::from_millis(10)).await;
            }
            reset.set_zero_linger().expect("a reset on close");
            drop(reset);
            // Room for the pipe to meet the reset while the run still listens.
            tokio::time::sleep(core::time::Duration::from_millis(50)).await;
        })
        .await;
        assert!(ended.is_none(), "still listening: {ended:?}");
        assert_eq!(err, "");
    }

    /// A download half whose Landed comes when `landed` fires, or never with none.
    struct Lands(io::DuplexStream, Option<oneshot::Receiver<()>>);
    impl io::AsyncRead for Lands {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut io::ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_read(cx, buf)
        }
    }
    impl super::Download for Lands {
        async fn landed(&mut self) -> io::Result<()> {
            match self.1.take() {
                Some(landed) => landed.await.map_err(|_| io::ErrorKind::BrokenPipe.into()),
                None => core::future::pending().await,
            }
        }
    }

    /// A pipe whose upload carried a byte ends only once the far side holds it, with no clock: the
    /// upload half's word by own bind, Landed on the download half through `serve`. An empty upload has
    /// nothing to wait for.
    #[tokio::test]
    async fn a_pipe_is_whole_once_the_far_side_holds_it() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        for (by_upload, up) in [(true, &b"ping"[..]), (false, b"ping"), (true, b"")] {
            let local = tokio::net::TcpListener::bind(("127.0.0.1", 0))
                .await
                .expect("a free port");
            let at = local.local_addr().expect("its address");
            let (near, accepted) = tokio::join!(tokio::net::TcpStream::connect(at), local.accept());
            let (mut near, (tcp, _)) = (near.expect("connect"), accepted.expect("accepted"));
            let (word, said) = oneshot::channel();
            // The half the word does not come on waits forever: its sender is held to the row's end.
            let (_never, unsaid) = oneshot::channel::<()>();
            let (write, mut far_in) = io::duplex(64);
            let (far_out, read) = io::duplex(64);
            let opened = if by_upload {
                super::Opened {
                    info: bifrost::ConnInfo::default(),
                    write: swoosh::testkit::TestWrite::read_by(write, said),
                    read: Lands(read, None),
                }
            } else {
                super::Opened {
                    info: bifrost::ConnInfo::default(),
                    write: swoosh::testkit::TestWrite::read_by(write, unsaid),
                    read: Lands(read, Some(said)),
                }
            };
            // The far side has sent all it will.
            drop(far_out);
            let splice = super::splice(tcp, opened);
            tokio::pin!(splice);
            // The local client's whole exchange, then room for the pipe to end were it to end early.
            let exchanged = async {
                near.write_all(up).await.expect("the upload");
                near.shutdown().await.expect("its end");
                let mut uploaded = vec![0; up.len()];
                far_in.read_exact(&mut uploaded).await.expect("carried");
                let _ = near.read_to_end(&mut Vec::new()).await;
                tokio::time::sleep(core::time::Duration::from_millis(100)).await;
            };
            let early = tokio::select! {
                ended = &mut splice => Some(ended),
                () = exchanged => None,
            };
            if up.is_empty() {
                assert!(matches!(early, Some(Ok(()))), "nothing to hold: {early:?}");
                continue;
            }
            assert!(
                early.is_none(),
                "{by_upload}: whole before the far side held it"
            );
            word.send(()).expect("the pipe waits");
            splice.await.expect("whole once held");
        }
    }

    /// A pipe's warning says why its open failed by kind, the same on both paths, with the machine's text
    /// escaped: own bind and through `serve`, each row's clause; an outcome that ends the run has none.
    #[test]
    fn a_failed_open_reads_by_its_kind() {
        use swoosh::peers::OpenError;
        use swoosh::serve::control_codec::{ControlError, OpenRefusal, PeerRefusal};
        use swoosh::streams::Unopened;

        use super::Failure;

        let detail = || bifrost::RefusalDetail::bounded("busy\u{1b}[2K");
        let clause = |unopened: Unopened| Failure::of(&unopened).map(|failure| failure.to_string());
        let rows = [
            (
                Unopened::from(OpenError::Open(bifrost::Error::Refused(
                    bifrost::Refusal::Unavailable { detail: detail() },
                ))),
                r"reached, but refused (unavailable: busy\u{1b}[2K)",
            ),
            (
                Unopened::from(OpenError::Open(bifrost::Error::Refused(
                    bifrost::Refusal::BadRequest { detail: detail() },
                ))),
                r"reached, but refused (bad request: busy\u{1b}[2K)",
            ),
            (Unopened::Own(OpenError::Timeout), "unreachable"),
            (
                Unopened::Own(OpenError::Unreachable(swoosh::peers::DialFailure::TimedOut)),
                "unreachable",
            ),
            (
                Unopened::Own(OpenError::Open(bifrost::Error::Stream(
                    "closed: secret-sentinel".into(),
                ))),
                "interrupted",
            ),
            (Unopened::Own(OpenError::Busy), "too many connections here"),
            (Unopened::Home(eyre::eyre!("unreadable")), "interrupted"),
            (
                Unopened::Refused(OpenRefusal::Unreachable(detail())),
                "unreachable",
            ),
            (Unopened::Refused(OpenRefusal::Timeout), "unreachable"),
            (
                Unopened::Refused(OpenRefusal::Broken(detail())),
                r"interrupted (busy\u{1b}[2K)",
            ),
            (
                Unopened::Refused(OpenRefusal::PeerUnreadable(detail())),
                "interrupted",
            ),
            (
                Unopened::Refused(OpenRefusal::Busy),
                "too many connections here",
            ),
            (Unopened::ServeError("disk full".to_owned()), "interrupted"),
            (
                Unopened::Control(ControlError::Timeout {
                    phase: "response read",
                }),
                "interrupted",
            ),
        ];
        for (unopened, expected) in rows {
            assert_eq!(clause(unopened).as_deref(), Some(expected));
        }
        for ends in [
            Unopened::Refused(OpenRefusal::Peer(PeerRefusal::NotAdmitted)),
            Unopened::Refused(OpenRefusal::StandingEnded),
            Unopened::Refused(OpenRefusal::NotHere),
            Unopened::ServeGone,
            Unopened::Skew,
        ] {
            assert_eq!(clause(ends), None, "an ending row never warns");
        }
    }

    /// The warning leads with the machine as a refusal does: its name; `that machine` for a key with no
    /// name; `the link's machine` for a link with no name, so a whole key never breaks the line.
    #[test]
    fn a_warning_names_the_machine_as_a_refusal_does() {
        let contacts = crate::commands::through_serve::tests::book();
        let key = bifrost::NodeId::from_ed25519_secret(&[0x63; 32]).to_string();
        let slip = swoosh::testkit::TestNode::seeded(1)
            .fleet_slip(
                &"ssh".parse().expect("a service"),
                swoosh::testkit::TestRoot::seeded(2).verify_key(),
                nauthy::Request::expires_in(core::time::Duration::from_secs(3600)),
            )
            .expect("a slip");
        let link = swoosh::link::Link::from(slip).to_string();
        for (typed, named) in [
            ("me/nas", "me/nas"),
            (key.as_str(), "that machine"),
            (link.as_str(), "the link's machine"),
        ] {
            let machine = crate::commands::through_serve::tests::machine(&contacts, typed);
            let mut err = Vec::new();
            super::PipeFailures::new(&machine, &mut err)
                .failed(Some(super::Failure::Unreachable), &eyre::eyre!("down"));
            assert_eq!(
                String::from_utf8(err).expect("utf-8"),
                format!(
                    "warning: a connection to {named} failed: unreachable\n  Still listening for new \
                     connections.\n"
                )
            );
        }
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

    /// The own bind's download half over `reader`, watching `session`, as a `Half` the run's `Peers`
    /// hands out watches the connection it rides.
    fn own_read(reader: bifrost_mem::MemRead, session: &bifrost_mem::MemSession) -> OwnRead<'_> {
        OwnRead {
            half: reader,
            session,
        }
    }

    /// A mem session's download half, with the session it rides.
    struct OwnRead<'s> {
        half: bifrost_mem::MemRead,
        session: &'s bifrost_mem::MemSession,
    }

    impl super::Download for OwnRead<'_> {
        async fn landed(&mut self) -> io::Result<()> {
            self.session.wait_closed().await;
            Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "session closed",
            ))
        }
    }

    impl io::AsyncRead for OwnRead<'_> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut io::ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.half).poll_read(cx, buf)
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
