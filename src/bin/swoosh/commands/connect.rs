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
//! Both sinks end when the host ends the session (it exited, or it cut the session on a revoke or an
//! expiry), whatever the local side is doing. tightbeam's own stdio bridge and port forward do not yet:
//! the bridge waits on a stdin read before the process can exit, and the forward keeps listening on a
//! session that is gone. So the exchange, the bridge and the forward live here, over tightbeam's wire
//! frames, until tightbeam's own end the same way.

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
pub async fn connect<T: Transport, D: Discovery>(
    node: &Node<T, D>,
    contacts: &Contacts,
    machine: &PeerMachine,
    service: Service,
    slot1: Option<Link>,
    slot2: Option<Link>,
    to: To,
) -> eyre::Result<()> {
    // The opening frame every stream sends.
    let request = Request {
        service: service.to_string(),
        capability: slot1.as_ref().map(ToString::to_string),
        membership: slot2.as_ref().map(ToString::to_string),
    };
    let dial = machine.key();
    let refused = Refused {
        machine,
        service: &service,
        slot1: &slot1,
        slot2: &slot2,
    };
    match to {
        To::Port(port) => forward_port(node, Machine::of(contacts, dial), &refused, &request, port)
            .await
            .map_err(escaped),
        To::Stdout => pipe_stdio(node, &refused, &request).await.map_err(escaped),
        // The path is not echoed: a typed path would read as a missing socket, not a missing feature.
        To::UnixListener(_) => {
            eyre::bail!("a unix:<path> local end is not built yet: use a port, or - for stdout")
        }
    }
}

/// Open one stream on `session` and ask the host for the service: the admitted halves, or the host's
/// refusal.
///
/// Every failure comes back as its own error, unwrapped, so a printed line names what failed (`early eof`,
/// the transport that does not prove the peer) and reads the same on both sinks.
async fn admitted<S: Session>(
    session: &S,
    request: &Request,
) -> eyre::Result<Result<(S::Write, S::Read), Refusal>> {
    let (mut writer, mut reader) = session.open_bi().await?;
    // The checked writer: a request presenting a credential refuses here, before any byte, when the
    // session's declared profile does not prove the peer.
    request.write_checked::<S, _>(&mut writer).await?;
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
}

/// Reach the peer, prove the gate admits this request, bind the local port, say so on stderr naming the
/// `machine`, then forward each local connection over its own stream until the session ends.
///
/// Admission is proven on one probe stream before the line prints, so a refusal fails here with the host's
/// reason rather than as a silent reset once the line is out. Every later stream presents the same request
/// to the same gate. stdout stays empty: the port was typed, so the line carries nothing a script needs,
/// and `forward`'s stdout is only ever the stream.
async fn forward_port<T: Transport, D: Discovery>(
    node: &Node<T, D>,
    machine: Machine,
    refused: &Refused<'_>,
    request: &Request,
    port: u16,
) -> eyre::Result<()> {
    let session = node.connect(refused.machine.key()).await?;
    // The probe stream is dropped once admitted; the host tears its half down.
    if let Err(refusal) = admitted(&session, request).await? {
        return Err(refused.on(&session, refusal).await);
    }
    let listener = TcpListener::bind(("127.0.0.1", port)).await?;
    eprintln!(
        "Forwarding {} on {machine} to 127.0.0.1:{port}.",
        request.service
    );
    press_ctrl_c();
    forward(&session, request, listener).await
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

/// The most local connections one forward or proxy holds at once, carried or waiting for a stream. Above a
/// QUIC peer's usual concurrent-stream limit (100 on iroh), and far enough below a default descriptor limit
/// (256 on macOS) that connections waiting for a stream cannot exhaust the process. Past it, new
/// connections wait in the kernel's listen backlog.
pub const MAX_PIPES: usize = 128;

/// How long a local listener waits before accepting again after an accept fails. An error such as running
/// out of descriptors repeats on every attempt until something frees, so retrying at once would spin.
pub const ACCEPT_RETRY: Duration = Duration::from_millis(100);

/// Forward each accepted local connection over its own stream, until the session ends: then the forward
/// is over, and every connection it carried has already ended with it.
async fn forward<S: Session>(
    session: &S,
    request: &Request,
    listener: TcpListener,
) -> eyre::Result<()> {
    let mut pipes = FuturesUnordered::new();
    let closed = session.wait_closed();
    tokio::pin!(closed);
    // Set after a failed accept: accepting resumes once `retry` fires.
    let retry = tokio::time::sleep(Duration::ZERO);
    tokio::pin!(retry);
    let mut paused = false;
    loop {
        tokio::select! {
            // The host closed the session (it cut it on a revoke or an expiry), or the path to it failed.
            () = &mut closed => return Err(lost(session).await),
            () = &mut retry, if paused => paused = false,
            // Accept only below the cap: a connection waiting for a stream holds a descriptor.
            accepted = listener.accept(), if !paused && pipes.len() < MAX_PIPES => match accepted {
                // The stream is opened inside the pipe: past the peer's stream limit an open waits, and
                // waiting here would stop the pipes in flight from being polled.
                Ok((tcp, _)) => pipes.push(carry(session, request, tcp)),
                // One failed accept drops no pipe in flight; pause, since it fails again at once.
                Err(error) => {
                    tracing::warn!(%error, "local accept failed; still listening");
                    retry.as_mut().reset(tokio::time::Instant::now() + ACCEPT_RETRY);
                    paused = true;
                }
            },
            Some(result) = pipes.next(), if !pipes.is_empty() => {
                // One connection's failure is not the forward's: it goes to the log, not to the person.
                if let Err(error) = result {
                    tracing::warn!("connection failed: {error:#}");
                }
            }
        }
    }
}

/// Carry one local connection over its own admitted stream, both ways, until both sides close.
async fn carry<S: Session>(session: &S, request: &Request, mut tcp: TcpStream) -> eyre::Result<()> {
    let (writer, reader) = admitted(session, request)
        .await?
        .map_err(bifrost::Error::Refused)?;
    io::copy_bidirectional(&mut tcp, &mut io::join(reader, writer)).await?;
    Ok(())
}

/// A forward's remote stream ended. No source chain can disclose a transport or cut reason.
#[derive(Debug, thiserror::Error)]
#[error("connection lost")]
struct ConnectionLost;

/// A transport cause is diagnostic context, never part of the command's terminal outcome. Asking the
/// closed session does not establish why the host ended it, so no cut reason is inferred here.
async fn lost<S: Session>(session: &S) -> eyre::Report {
    if let Err(error) = session.open_bi().await {
        tracing::debug!(cause = %swoosh::escape::Escaped(&swoosh::escape::causes(&error)), "connection lost");
    }
    ConnectionLost.into()
}

/// Reach the service over one stream and pipe it against this process's stdin and stdout: the bridge
/// `swoosh ssh` runs as its `ProxyCommand`.
///
/// The pump ends on the host's half: when the stream from the host ends or errors (the remote command
/// exited, or the host cut the session on a revoke or an expiry), the run is over, whatever stdin is
/// doing. stdin is read on its own thread (see [`stdin_chunks`]), so nothing waits on a read that, at a
/// terminal or under ssh, only returns when the person types again.
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
    pump_stdio(writer, reader, stdin_chunks()?, io::stdout()).await
}

/// Endpoint provenance, not session closure, identifies a failed remote stream: its error can arrive
/// before the session's close signal. Local stdin/stdout failures stay local even after a host cut.
async fn pump_stdio(
    mut writer: impl io::AsyncWrite + Unpin,
    reader: impl io::AsyncRead + Unpin,
    mut input: mpsc::Receiver<io::Result<Vec<u8>>>,
    mut output: impl io::AsyncWrite + Unpin,
) -> eyre::Result<()> {
    let mut reader = RemoteReader(reader);
    let upstream = async {
        while let Some(chunk) = input.recv().await {
            writer.write_all(&chunk?).await.map_err(remote_failure)?;
        }
        writer.shutdown().await.map_err(remote_failure)
    };
    let downstream = async {
        io::copy(&mut reader, &mut output)
            .await
            .map_err(read_failure)?;
        output.flush().await?;
        Ok::<(), eyre::Report>(())
    };
    // A pending stdout write can leave remote bytes inside the copy's buffer. Keep that same
    // operation through stdin EOF so a successful half-close cannot discard already consumed bytes.
    tokio::pin!(downstream);
    tokio::select! {
        // The host's half ended or failed: the run is over. The stdin pump is dropped, never awaited.
        result = &mut downstream => result?,
        // stdin ended first (a piped, finite input), or the write toward the host failed. A clean end
        // half-closes toward the host, then the host's remaining output still drains to stdout.
        result = upstream => {
            result?;
            downstream.await?;
        }
    }
    Ok(())
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
fn stdin_chunks() -> eyre::Result<mpsc::Receiver<io::Result<Vec<u8>>>> {
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

    #[tokio::test]
    async fn a_cut_has_no_printable_source_even_with_a_hostile_cause() {
        for session in [
            HostilePeer::RefusesStreams("secret-sentinel\r\nexpired\u{202e}"),
            HostilePeer::Unreachable("transport cause"),
            HostilePeer::HangsUp,
        ] {
            let report = super::lost(&session).await;
            assert!(report.is::<super::ConnectionLost>());
            assert_eq!(report.chain().count(), 1);
            assert_eq!(format!("error: {report:#}\n"), "error: connection lost\n");
            assert_eq!(
                format!("error: {:#}\n", super::escaped(report)),
                "error: connection lost\n"
            );
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
            super::pump_stdio(io::sink(), FailedReader, input, io::sink())
                .now_or_never()
                .expect("a remote read fails without waiting for closure"),
        );
        let (stdin, input) = mpsc::channel(1);
        drop(stdin);
        let (writer, reader) = after_half_close(FailedReader);
        assert_remote(
            super::pump_stdio(writer, reader, input, io::sink())
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
                super::pump_stdio(FailedWriter(at), PendingReader, input, io::sink())
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
            super::pump_stdio(io::sink(), PendingReader, input, io::sink())
                .now_or_never()
                .expect("a local stdin error is ready"),
        );
        for at in [WriteFailure::Write, WriteFailure::Flush] {
            let (_stdin, input) = mpsc::channel(1);
            assert_local(
                super::pump_stdio(io::sink(), &b"out"[..], input, FailedWriter(at))
                    .now_or_never()
                    .expect("a local stdout error is ready"),
            );
            let (stdin, input) = mpsc::channel(1);
            drop(stdin);
            let (writer, reader) = after_half_close(&b"out"[..]);
            assert_local(
                super::pump_stdio(writer, reader, input, FailedWriter(at))
                    .now_or_never()
                    .expect("a post-half-close stdout error stays local"),
            );
        }
    }

    #[tokio::test]
    async fn a_clean_remote_eof_ends_with_stdin_still_open() {
        let (_stdin, input) = mpsc::channel(1);
        assert!(
            super::pump_stdio(io::sink(), io::empty(), input, io::sink())
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
            super::pump_stdio(writer, reader, input, &mut output)
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
            let pump = super::pump_stdio(HalfCloseWriter(Some(closed)), reader, input, output);
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
            let report = async {
                let session = super::lost(&HostilePeer::RefusesStreams(HOSTILE)).await;
                assert_eq!(format!("error: {session:#}\n"), "error: connection lost\n");
                super::remote_failure(fault())
            }
            .with_subscriber(subscriber)
            .await;
            assert_eq!(format!("error: {report:#}\n"), "error: connection lost\n");
            let printed = String::from_utf8(Vec::clone(&bytes.lock().unwrap())).unwrap();
            if directives.is_some() {
                assert!(printed.contains(ESCAPED), "{printed:?}");
                assert!(!printed.contains(HOSTILE));
                assert_eq!(printed.lines().count(), 2);
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
            &Contacts::default(),
            &machine,
            service,
            None,
            None,
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
            &contacts,
            &machine,
            "ssh".parse().expect("a service"),
            None,
            None,
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
            1,
            "the follow-up rides the refused dial's session"
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
}
