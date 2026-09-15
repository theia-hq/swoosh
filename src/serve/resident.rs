//! The `--resident` run glue: the live catalog reads plus the control listener arm.
//!
//! `Resident` is the state the accept loop serves from: the pid, the start time, the served catalog
//! snapshot, the live disabled-list path, and a CLONE of the node's teardown token (the exposer stays
//! the single teardown owner; this arm only REQUESTS the stop, never tears anything down itself).

use core::net::SocketAddr;
use core::sync::atomic::{AtomicU64, Ordering};
use core::time::Duration;
use std::os::unix::io::AsRawFd as _;
use std::path::PathBuf;
use std::sync::Arc;

use bifrost::NodeId;
use tightbeam::tunnel::{CancellationToken, ServiceCatalog};
use tokio::io::AsyncWriteExt as _;
use tokio::sync::Semaphore;

use super::control::{
    ControlError, DisabledList, MAX_STATUS_STRING, Request, Response, ServiceMenu, StatusReply,
};
use crate::node_client::{NodeClient, euid, real_peer_uid};

/// Seconds a control connection may sit idle before it is reaped (the slow-loris bound).
pub const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Concurrent control connections served at once; past the cap, connections queue at the listener
/// (the `MAX_SESSIONS` backpressure pattern), so a flood queues rather than pinning a task each.
pub const MAX_CONTROL_CONNS: usize = 8;

/// The largest slice of `<home>/disabled` one status read inspects: enough for any legitimate
/// disable list, bounded so a same-uid writer cannot make the daemon allocate on demand.
pub const DISABLED_BYTES_CAP: u64 = 64 * 1024;

/// The most disabled names one status reply reports, mirroring the codec's decode cap
/// (`control.rs`), so a grown file can never produce a reply the client refuses to decode.
pub const DISABLED_NAMES_CAP: usize = 1024;

/// How long the accept loop waits after a recoverable accept error before retrying: enough for
/// transient resource pressure (EMFILE/ENOBUFS) to clear, short enough that a stop lands promptly.
pub const ACCEPT_BACKOFF: Duration = Duration::from_millis(50);

/// The resident state the accept loop serves from. Built once at `--resident` start; every query
/// reads the LIVE disabled file, never a cached copy, so the socket is never a data channel into
/// the gate.
pub struct Resident {
    /// The resident's pid, reported in the status reply.
    pid: u32,
    /// When the resident started, for the uptime reply.
    started_at: std::time::Instant,
    /// This node's id, reported in the status reply.
    node_id: NodeId,
    /// The bound address, when the transport hands one out.
    addr: Option<SocketAddr>,
    /// The served catalog snapshot (the same snapshot `run_serve` cuts for `control.services`).
    catalog: ServiceCatalog,
    /// `<home>/disabled`: re-read per query, the sole toggle mechanism.
    disabled_path: PathBuf,
    /// A CLONE of the node's teardown token: firing it REQUESTS the stop; the exposer acts on it.
    cancel: CancellationToken,
    /// How the node stopped, once a path fires the token (ctrl-c, expires, wire stop, socket stop).
    stop_source: Arc<StopSource>,
    /// The concurrency cap the accept loop acquires BEFORE spawning a task.
    conns: Arc<Semaphore>,
    /// Connections served so far (the BLOCKER-3 oracle: a disable must move ZERO control traffic).
    served: Arc<AtomicU64>,
}

impl Resident {
    /// Build the resident state over the served catalog and the teardown token clone.
    pub fn new(
        node_id: NodeId,
        addr: Option<SocketAddr>,
        catalog: ServiceCatalog,
        disabled_path: PathBuf,
        cancel: CancellationToken,
    ) -> Self {
        Self {
            pid: std::process::id(),
            started_at: std::time::Instant::now(),
            node_id,
            addr,
            catalog,
            disabled_path,
            cancel,
            stop_source: Arc::new(StopSource::new()),
            conns: Arc::new(Semaphore::new(MAX_CONTROL_CONNS)),
            served: Arc::new(AtomicU64::new(0)),
        }
    }

    /// The stop-source bookkeeping shared with the serve select arms.
    pub fn stop_source(&self) -> Arc<StopSource> {
        Arc::clone(&self.stop_source)
    }

    /// The concurrency cap (for tests driving the listener directly).
    pub fn semaphore(&self) -> Arc<Semaphore> {
        Arc::clone(&self.conns)
    }

    /// Connections served so far.
    pub fn served(&self) -> u64 {
        self.served.load(Ordering::Relaxed)
    }

    /// Answer one decoded request without side effects: `Stop` is answered [`Response::Ack`], and the
    /// matching teardown is [`fire_stop`](Self::fire_stop), fired by the serve path only AFTER the
    /// Ack is on the wire so a socket stop can never lose its confirm to the stop it triggers.
    pub fn answer(&self, request: Request) -> Response {
        match request {
            Request::Services => Response::Catalog(self.menu()),
            Request::Status => Response::Status(self.status_reply()),
            Request::Stop => Response::Ack,
        }
    }

    /// Fire the socket stop: record the local source (so the run classifies the stop as local, never
    /// as a wire `control.stop`) and cancel the one teardown token. Split from
    /// [`answer`](Self::answer) so the Ack is written first: cancelling before the confirm let the
    /// process exit out from under the reply.
    pub fn fire_stop(&self) {
        self.stop_source.note_socket();
        self.cancel.cancel();
    }

    /// Cut a fresh status reply: the public shape only, with the live menu re-read live and the warm
    /// peer list empty until the cache lands.
    fn status_reply(&self) -> StatusReply {
        StatusReply {
            node_id: self.node_id,
            pid: self.pid,
            addr: self.addr,
            uptime_secs: self.started_at.elapsed().as_secs(),
            menu: self.menu(),
            warm: Vec::new(),
        }
    }

    /// The live service menu: the served catalog snapshot plus the disabled list re-read live.
    fn menu(&self) -> ServiceMenu {
        ServiceMenu {
            catalog: self.catalog.clone(),
            disabled: read_disabled_names(&self.disabled_path),
        }
    }

    /// The live disabled list, re-read per query.
    pub fn disabled_names(&self) -> DisabledList {
        read_disabled_names(&self.disabled_path)
    }

    /// Serve the bound std listener until the teardown token fires: the third arm of the serve
    /// select. A slot is taken BEFORE each accept, so at the cap the loop parks on the semaphore and
    /// connections stay queued at the listener (the `MAX_SESSIONS` backpressure pattern) rather than
    /// being accepted and dropped: a one-shot client cannot lose the race to a same-uid flood. Each
    /// accepted connection is uid-checked BEFORE a byte is read, served one-shot under the read
    /// timeout, then closed.
    pub async fn serve(
        self: Arc<Self>,
        listener: std::os::unix::net::UnixListener,
    ) -> eyre::Result<()> {
        listener.set_nonblocking(true)?;
        let listener = tokio::net::UnixListener::from_std(listener)?;
        loop {
            // Acquire BEFORE accepting: the acquire future doubles as the wake-up when a slot frees
            // (a gated `available_permits() > 0` check would need a separate wake and could park at
            // the cap forever), and the cancel token stays a sibling arm so a stop never waits on
            // the listener.
            let permit = tokio::select! {
                () = self.cancel.cancelled() => return Ok(()),
                permit = self.conns.clone().acquire_owned() => match permit {
                    Ok(permit) => permit,
                    // The semaphore is never closed; an unexpected close is the teardown signal.
                    Err(_) => return Ok(()),
                },
            };
            let accepted = tokio::select! {
                () = self.cancel.cancelled() => return Ok(()),
                accepted = listener.accept() => accepted,
            };
            match accepted {
                Ok((stream, _)) => {
                    let this = Arc::clone(&self);
                    tokio::spawn(async move {
                        let _permit = permit;
                        this.serve_one(stream).await;
                    });
                }
                Err(error) if accept_error_fatal(&error) => {
                    // A listener-level error (a bad descriptor, a non-socket) cannot clear by
                    // retrying: stop the arm so the run fails loudly instead of backing off
                    // forever on a control socket that can never answer.
                    return Err(eyre::eyre!("control listener failed: {error}"));
                }
                Err(error) => {
                    // A recoverable error (fd pressure: EMFILE/ENFILE/ENOBUFS) would re-fire
                    // immediately and spin the same runtime the exposer serves on, so wait one
                    // short bounded backoff before the next accept. The loop re-checks the
                    // cancel token after it, so a stop during the backoff lands promptly.
                    tracing::warn!(%error, "control accept failed; backing off");
                    drop(permit);
                    accept_backoff_wait().await;
                }
            }
        }
    }

    /// Serve one accepted connection under the production peer-credential check and read deadline.
    async fn serve_one(&self, stream: tokio::net::UnixStream) {
        self.serve_checked_with(stream, real_peer_uid, READ_TIMEOUT)
            .await;
    }

    /// Serve one connection under an injectable peer-credential checker and timeout: the uid check,
    /// then one request and one response, then close. Split from [`serve_one`](Self::serve_one) so
    /// tests fake a foreign uid without root and drive the real read path with a short deadline
    /// instead of pinning the constant; production passes [`READ_TIMEOUT`].
    ///
    /// A `Stop` is acked BEFORE [`fire_stop`](Self::fire_stop) cancels the node: the write is the
    /// last thing between the request and the process teardown the request itself triggers, so the
    /// confirm can never lose the race to exit.
    async fn serve_checked_with(
        &self,
        stream: tokio::net::UnixStream,
        checker: fn(i32) -> std::io::Result<u32>,
        timeout: Duration,
    ) {
        let fd = stream.as_raw_fd();
        match peer_uid(fd, checker) {
            Ok(uid) if uid == euid() => {}
            Ok(uid) => {
                tracing::warn!(uid, "refusing control connection from another user");
                return;
            }
            Err(error) => {
                tracing::warn!(%error, "could not check control peer credentials; refusing");
                return;
            }
        }
        self.served.fetch_add(1, Ordering::Relaxed);
        let (reader, mut writer) = stream.into_split();
        let mut reader = tokio::io::BufReader::new(reader);
        let request = tokio::time::timeout(timeout, Request::read(&mut reader)).await;
        let (response, stop) = match request {
            Ok(Ok(Request::Stop)) => (Response::Ack, true),
            Ok(Ok(request)) => (self.answer(request), false),
            Ok(Err(ControlError::TooLarge(_))) => {
                // EOF is the contract for an oversized DECLARED frame: the codec refuses the length
                // before reading a byte of it (`control.rs`), and the connection closes with no
                // reply. Replying `Error` would answer an attacker-chosen length while the client
                // may still be sending the payload it declared, so the close is the whole response.
                // The serve-level test (`oversized_declared_frame_ends_the_connection`) pins this.
                return;
            }
            Ok(Err(error)) => (Response::Error(error.to_string()), false),
            Err(_elapsed) => {
                return;
            }
        };
        self.reply_then_fire(&mut writer, &response, stop, timeout)
            .await;
        let _ = writer.shutdown().await;
    }

    /// Write the reply, THEN fire the stop it answered: the order is the stop-Ack contract, the
    /// last thing between a socket `Stop` and the process teardown that stop triggers. Split into
    /// its own generic method so a test drives it with a writer that never completes and observes
    /// that the cancel stays unfired while the Ack write is pending.
    async fn reply_then_fire<W>(
        &self,
        writer: &mut W,
        response: &Response,
        stop: bool,
        timeout: Duration,
    ) where
        W: tokio::io::AsyncWrite + Unpin,
    {
        let _ = tokio::time::timeout(timeout, response.write(writer)).await;
        if stop {
            self.fire_stop();
        }
    }
}

/// The resident is the in-process server implementation of the control contract: the same
/// [`NodeClient`] the socket client speaks, so the accept path and a local client cannot drift.
/// `services`/`status` build the same replies the accept path sends (through the shared private
/// helpers); `stop` is the teardown the socket `Stop` triggers (the accept path acks first, then
/// fires it, so the confirm is never lost to the stop it triggers).
impl NodeClient for Resident {
    async fn services(&self) -> Result<ServiceMenu, ControlError> {
        Ok(self.menu())
    }

    async fn status(&self) -> Result<StatusReply, ControlError> {
        Ok(self.status_reply())
    }

    async fn stop(&self) -> Result<(), ControlError> {
        self.fire_stop();
        Ok(())
    }
}

/// Read the live disabled names from `<home>/disabled`: one trimmed non-empty name per line, an
/// absent file meaning none. Total (any name is a valid thing to disable), mirroring the oracle's
/// decode without depending on its debounce state.
///
/// Bounded and honest: at most [`DISABLED_BYTES_CAP`] bytes are read, at most
/// [`DISABLED_NAMES_CAP`] names reported, and every name must fit the reply's own
/// [`MAX_STATUS_STRING`] cap; a read failure, an oversized file, or an oversize name is an
/// explicit [`DisabledList::Unknown`], never an empty "nothing disabled" the gate would contradict
/// or a frame the client refuses to decode.
fn read_disabled_names(path: &std::path::Path) -> DisabledList {
    use std::io::Read as _;

    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {
            return DisabledList::Known(Vec::new());
        }
        Err(error) => return DisabledList::Unknown(error.to_string()),
    };
    // Read one byte past the cap so an oversized file is detectable, not silently truncated: a
    // truncated list would under-report exactly like the false empty this fix removes.
    let mut reader = file.take(DISABLED_BYTES_CAP + 1);
    let mut text = String::new();
    if let Err(error) = reader.read_to_string(&mut text) {
        return DisabledList::Unknown(error.to_string());
    }
    if text.len() as u64 > DISABLED_BYTES_CAP {
        return DisabledList::Unknown("the disabled file exceeds the read cap".to_owned());
    }
    let mut names = Vec::new();
    for name in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
        if name.len() > MAX_STATUS_STRING {
            return DisabledList::Unknown(format!(
                "a disabled name exceeds the {MAX_STATUS_STRING}-byte reply cap"
            ));
        }
        names.push(name.to_owned());
    }
    names.sort();
    names.truncate(DISABLED_NAMES_CAP);
    DisabledList::Known(names)
}

/// Wait one bounded [`ACCEPT_BACKOFF`] before retrying a recoverable accept error. A named helper so
/// the wait is itself a unit under test: the predicate test (`accept_errors_split_fatal_from_backoff`)
/// can prove the classification but never whether the loop actually sleeps, and inducing a real
/// EMFILE/ENOBUFS in a test is process-global and flaky.
async fn accept_backoff_wait() {
    tokio::time::sleep(ACCEPT_BACKOFF).await;
}

/// Whether an accept error is fatal for the listener: a bad descriptor or a non-socket cannot
/// clear by retrying, so the arm ends the run instead of backing off forever. Everything else
/// (fd pressure, connection aborts) is treated as recoverable and takes the bounded backoff;
/// `WouldBlock`/`EINTR` never reach here because tokio's readiness machinery absorbs them.
fn accept_error_fatal(error: &std::io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::EBADF | libc::EFAULT | libc::EINVAL | libc::ENOTSOCK)
    )
}

/// Which path fired the teardown token. Recorded once (first writer wins), never collapsing the
/// socket stop into the wire `control.stop` one: each trigger keeps its own bookkeeping.
pub struct StopSource {
    /// The first recorded source, if any.
    first: std::sync::Mutex<Option<StopKind>>,
}

/// How the node was asked to stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopKind {
    /// The local operator pressed Ctrl-C.
    Interrupted,
    /// A `--expires` deadline elapsed.
    Expires,
    /// An admitted wire `control.stop` caller.
    Wire,
    /// A local-uid socket `Stop`.
    Socket,
}

impl StopSource {
    /// An empty source: nothing has fired yet.
    pub fn new() -> Self {
        Self {
            first: std::sync::Mutex::new(None),
        }
    }

    /// Record a kind, first writer wins.
    pub fn note(&self, kind: StopKind) {
        if let Ok(mut first) = self.first.lock() {
            if first.is_none() {
                *first = Some(kind);
            }
        }
    }

    /// Record the socket stop.
    pub fn note_socket(&self) {
        self.note(StopKind::Socket);
    }

    /// The first recorded source, if any.
    pub fn first(&self) -> Option<StopKind> {
        self.first.lock().ok().and_then(|guard| *guard)
    }
}

impl Default for StopSource {
    fn default() -> Self {
        Self::new()
    }
}

/// Read the peer uid for `fd`: macOS `getpeereid`, Linux `SO_PEERCRED`. The `checker` indirection
/// lets tests fake a foreign uid without root.
fn peer_uid(fd: i32, checker: fn(i32) -> std::io::Result<u32>) -> std::io::Result<u32> {
    checker(fd)
}

#[cfg(test)]
#[path = "serve_resident_tests.rs"]
mod resident_tests;
