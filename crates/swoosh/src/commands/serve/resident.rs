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
    ControlError, DisabledList, MAX_STATUS_STRING, Request, Response, StatusReply,
};

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

    /// Answer one decoded request: two live reads and a stop. The ONLY state-changing op is `Stop`,
    /// which cancels the token clone and records the socket as the stop source.
    pub fn answer(&self, request: Request) -> Response {
        match request {
            Request::Services => Response::Catalog(self.catalog.clone()),
            Request::Status => Response::Status(self.status()),
            Request::Stop => {
                self.stop_source.note_socket();
                self.cancel.cancel();
                Response::Ack
            }
        }
    }

    /// Cut a fresh status reply: the public shape only, with the disabled list re-read live.
    fn status(&self) -> StatusReply {
        StatusReply {
            node_id: self.node_id,
            pid: self.pid,
            addr: self.addr,
            uptime_secs: self.started_at.elapsed().as_secs(),
            catalog: self.catalog.clone(),
            disabled: read_disabled_names(&self.disabled_path),
        }
    }

    /// The live disabled list, re-read per query.
    pub fn disabled_names(&self) -> DisabledList {
        read_disabled_names(&self.disabled_path)
    }

    /// Serve the bound std listener until the teardown token fires: the third arm of the serve
    /// select. Each accepted connection is uid-checked BEFORE a byte is read, served one-shot
    /// under the read timeout, then closed.
    pub async fn serve(
        self: Arc<Self>,
        listener: std::os::unix::net::UnixListener,
    ) -> eyre::Result<()> {
        listener.set_nonblocking(true)?;
        let listener = tokio::net::UnixListener::from_std(listener)?;
        loop {
            tokio::select! {
                () = self.cancel.cancelled() => return Ok(()),
                accepted = listener.accept() => match accepted {
                    Ok((stream, _)) => {
                        // Acquire BEFORE any spawn: past the cap, connections queue at the listener
                        // instead of each pinning a task set.
                        let Ok(permit) = self.conns.clone().try_acquire_owned() else {
                            drop(stream);
                            continue;
                        };
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
                        tokio::time::sleep(ACCEPT_BACKOFF).await;
                    }
                }
            }
        }
    }

    /// Serve one accepted connection: uid-check first, then one request and one response, then
    /// close. A foreign uid is warned and closed before a byte is read; a slow peer is reaped at
    /// the read timeout; an oversized frame is refused.
    async fn serve_one(&self, stream: tokio::net::UnixStream) {
        self.serve_checked(stream, real_peer_uid).await;
    }

    /// Serve one connection under the given peer-credential checker: the uid check, then one
    /// request and one response, then close. Split from [`serve_one`](Self::serve_one) so tests
    /// inject a fake foreign uid without root.
    async fn serve_checked(
        &self,
        stream: tokio::net::UnixStream,
        checker: fn(i32) -> std::io::Result<u32>,
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
        let request = tokio::time::timeout(READ_TIMEOUT, Request::read(&mut reader)).await;
        let response = match request {
            Ok(Ok(request)) => self.answer(request),
            Ok(Err(ControlError::TooLarge(_))) => {
                return;
            }
            Ok(Err(error)) => Response::Error(error.to_string()),
            Err(_elapsed) => {
                return;
            }
        };
        let _ = tokio::time::timeout(READ_TIMEOUT, response.write(&mut writer)).await;
        let _ = writer.shutdown().await;
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

/// The effective uid: the owner every control peer must match.
fn euid() -> u32 {
    // SAFETY: `geteuid` takes no arguments and touches no memory.
    unsafe { libc::geteuid() }
}

/// Read the peer uid for `fd`: macOS `getpeereid`, Linux `SO_PEERCRED`. The `checker` indirection
/// lets tests fake a foreign uid without root.
fn peer_uid(fd: i32, checker: fn(i32) -> std::io::Result<u32>) -> std::io::Result<u32> {
    checker(fd)
}

/// The production peer-credential read: `getpeereid` on macOS/BSD, `SO_PEERCRED` on Linux.
fn real_peer_uid(fd: i32) -> std::io::Result<u32> {
    #[cfg(target_os = "macos")]
    {
        let mut uid: libc::uid_t = 0;
        let mut gid: libc::gid_t = 0;
        // SAFETY: `fd` is the live fd of the accepted stream (borrowed, still open for this
        // call), and `uid`/`gid` are valid stack slots for the out params.
        let ok = unsafe { libc::getpeereid(fd, &mut uid, &mut gid) };
        if ok != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(uid)
    }
    #[cfg(target_os = "linux")]
    {
        let mut cred: libc::ucred = unsafe { core::mem::zeroed() };
        let mut len = core::mem::size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: `fd` is the live accepted-stream fd; `cred`/`len` are valid out-param slots
        // sized exactly for `SO_PEERCRED`.
        let ok = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut cred as *mut libc::ucred).cast::<libc::c_void>(),
                &mut len,
            )
        };
        if ok != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(cred.uid)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = fd;
        Err(std::io::Error::other(
            "peer credentials are not supported on this platform",
        ))
    }
}

/// Convert a blocking std listener into a tokio one without blocking the reactor: set
/// nonblocking first, then wrap. Kept here (not inline in `serve`) so the why stays with the how.
#[allow(dead_code)]
fn tokio_listener(
    listener: std::os::unix::net::UnixListener,
) -> std::io::Result<tokio::net::UnixListener> {
    listener.set_nonblocking(true)?;
    tokio::net::UnixListener::from_std(listener)
}

#[cfg(test)]
#[path = "serve_resident_tests.rs"]
mod resident_tests;
