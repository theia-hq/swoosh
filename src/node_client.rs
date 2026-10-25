//! Shared node control and the local-only service-detail client.
//!
//! [`NodeClient`] covers the menu, status and stop. Local service detail is an
//! inherent method on [`UidSocket`] and [`ControlClient`], not a remote operation.
//! The control value types live in [`crate::serve::control_codec`].

use core::future::Future;
use core::time::Duration;
use std::io;
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _};
use std::os::unix::io::AsRawFd as _;
use std::path::PathBuf;

use tokio::io::AsyncReadExt as _;
use tokio::net::UnixStream;
use tokio::time::timeout;

use crate::home::{Home, ProcessId};
use crate::serve::control_codec::{
    ControlError, LocalServiceSnapshot, Request, Response, ServiceMenu, StatusReply,
};

/// How long a connect to the local control socket may take before it is a [`ControlError::Timeout`].
/// A local listener admits at once; this bounds only a wedged path, never a normal dial.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// How long writing one control request or reading one response may take. The read bound mirrors the
/// server's own `READ_TIMEOUT`, so a client never sits longer than the server would.
const IO_TIMEOUT: Duration = Duration::from_secs(5);

/// The control surface every node backend serves: read the menu, read status, stop. One behavior home
/// so the uid-socket client and the resident implement the same contract and a behavior change lands
/// once.
///
/// The methods return `impl Future` (RPITIT, matching `Handler::serve` and `Reaching::run`), NOT
/// `impl Future + Send`: nothing spawns a `NodeClient` future, and the transport's `Session` contract
/// is deliberately not `Send`-bounded, so a `Send` demand here would force that contract to change for
/// the daemon's convenience.
pub trait NodeClient {
    /// The live service menu: the served catalog plus the LIVE disabled list.
    fn services(&self) -> impl Future<Output = Result<ServiceMenu, ControlError>>;
    /// The public status shape: id, pid, address, uptime, the live menu, the warm peers.
    fn status(&self) -> impl Future<Output = Result<StatusReply, ControlError>>;
    /// Request a graceful stop. Success does not prove that the process has exited.
    fn stop(&self) -> impl Future<Output = Result<(), ControlError>>;
}

/// Local resident control over a Unix socket, with one connection per exchange.
///
/// Before each request, check the connected peer's kernel-reported UID and listener PID. The UID must
/// match this process's effective UID, and the PID must match the selected home's record read after
/// connecting.
///
/// These checks establish account and recorded-listener attribution, not executable identity. They do
/// not protect against malicious mutation of the home or runtime namespace by the same account.
#[derive(Debug)]
pub struct UidSocket {
    /// The verified control socket path.
    socket: PathBuf,
    // Selected state, not cached authentication: every connected exchange rereads its PID.
    home: Home,
}

impl UidSocket {
    /// Resolve the selected home's control socket and check its path ownership, directory permissions
    /// and file types without connecting. These path checks do not identify a listener; each exchange
    /// checks the connected peer before sending a request.
    pub fn resolve(home: &Home) -> Result<Self, ControlError> {
        // No addressable runtime root (XDG_RUNTIME_DIR unset or relative, confstr failed) means no
        // resident is addressable under this home, not an insecure path.
        let socket = home
            .control_socket()
            .map_err(|_| ControlError::NoResident)?;
        Self::resolve_socket(home, socket)
    }

    /// Verify an already-derived socket path (the path half of [`resolve`](Self::resolve)), split out
    /// so tests can drive the ownership/mode/socket checks without resolving a process-global runtime
    /// root. Never connects.
    fn resolve_socket(home: &Home, socket: PathBuf) -> Result<Self, ControlError> {
        Self::resolve_socket_as(home, socket, euid(), euid())
    }

    /// [`resolve_socket`](Self::resolve_socket) with the expected owners injected: production passes
    /// [`euid`] for both halves, tests pass a foreign uid for one half to pin each comparison without
    /// root. The refused half names itself in the error, so a test can prove which check refused.
    fn resolve_socket_as(
        home: &Home,
        socket: PathBuf,
        dir_uid: u32,
        socket_uid: u32,
    ) -> Result<Self, ControlError> {
        let dir = match socket.parent() {
            Some(dir) => dir.to_owned(),
            None => return Err(ControlError::Untrusted { path: socket }),
        };
        // Step 1: the leaf dir must be this user's 0700 directory. A missing leaf is NoResident; a
        // present-but-wrong one (owner, mode, or a symlink) is Untrusted.
        let dir_meta =
            std::fs::symlink_metadata(&dir).map_err(|error| match error.raw_os_error() {
                Some(libc::ENOENT) => ControlError::NoResident,
                _ => ControlError::Untrusted { path: dir.clone() },
            })?;
        if !dir_meta.is_dir()
            || dir_meta.uid() != dir_uid
            || dir_meta.permissions().mode() & 0o777 != 0o700
        {
            return Err(ControlError::Untrusted { path: dir });
        }
        // Step 2: the socket must be a socket owned by this user. ENOENT is NoResident; a non-socket
        // inode, a foreign owner, or a stat failure is Untrusted.
        match std::fs::symlink_metadata(&socket) {
            Ok(meta) if meta.file_type().is_socket() && meta.uid() == socket_uid => {}
            Ok(_) => return Err(ControlError::Untrusted { path: socket }),
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {
                return Err(ControlError::NoResident);
            }
            Err(_) => return Err(ControlError::Untrusted { path: socket }),
        }
        Ok(Self {
            socket,
            home: Home::clone(home),
        })
    }

    /// Read one startup service snapshot through the local socket client.
    ///
    /// Uses the same connected-peer checks as other local control requests, with no status fallback or
    /// remote route. The snapshot does not prove backend health.
    ///
    /// # Errors
    ///
    /// Returns control trust, transport, framing or typed local-detail failures. A socket miss does not
    /// establish that the home's serve lock is free.
    pub async fn local_service_detail(&self) -> Result<LocalServiceSnapshot, ControlError> {
        self.exchange(&Request::LocalServiceDetail)
            .await?
            .into_local_snapshot()
    }

    /// Connect within the deadline, then check the kernel-reported peer UID and listener PID against
    /// this process's effective UID and the selected home's PID record read after connecting. Reject
    /// missing, invalid or mismatched attribution before writing request bytes.
    async fn connect(&self) -> Result<(UnixStream, ProcessId), ControlError> {
        self.connect_checked_with(UnixStream::connect(&self.socket), real_peer_credentials)
            .await
    }

    // Injection changes only the kernel query, never the post-connect record read or ordering.
    async fn connect_checked_with<C>(
        &self,
        dial: C,
        checker: fn(i32) -> io::Result<PeerCredentials>,
    ) -> Result<(UnixStream, ProcessId), ControlError>
    where
        C: Future<Output = std::io::Result<UnixStream>>,
    {
        let stream = timeout(CONNECT_TIMEOUT, dial)
            .await
            .map_err(|_| ControlError::Timeout { phase: "connect" })?
            .map_err(|error| match error.raw_os_error() {
                // The resident is gone (crash plant or never bound): a typed miss, not an I/O error.
                Some(libc::ENOENT | libc::ECONNREFUSED) => ControlError::NoResident,
                _ => ControlError::Io(error),
            })?;
        let untrusted = || ControlError::Untrusted {
            path: PathBuf::clone(&self.socket),
        };
        let peer = checker(stream.as_raw_fd()).map_err(|_| untrusted())?;
        let recorded = crate::home::ServeLock::checked_pid(&self.home).map_err(|_| untrusted())?;
        if peer.uid != euid() || recorded != peer.pid {
            return Err(untrusted());
        }
        Ok((stream, peer.pid))
    }

    /// Request a graceful stop and return the kernel-reported listener PID checked on that connection
    /// against the selected home's record read after connecting.
    ///
    /// After the complete request is written, success requires a complete acknowledgement or EOF before
    /// any response byte. EOF after any response byte is an error, not a stop confirmation. One
    /// five-second deadline covers the whole response read.
    ///
    /// Success does not prove that the process has exited.
    ///
    /// # Errors
    ///
    /// Returns an error if attribution or request writing fails, the node refuses the request, the
    /// response is truncated or invalid, or the response deadline expires.
    pub async fn stop_attributed(&self) -> Result<ProcessId, ControlError> {
        let (stream, pid) = self.connect().await?;
        Self::stop_on(stream, pid).await
    }

    async fn stop_on<S>(mut stream: S, pid: ProcessId) -> Result<ProcessId, ControlError>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        Self::write_request(&mut stream, &Request::Stop).await?;
        // Prefetch only one byte, replaying it into the unchanged codec. Once any response
        // begins, its truncation is an error; only a zero-byte close can stand in for an Ack.
        // The same deadline encloses both the prefetch and the entire declared frame.
        let response = timeout(IO_TIMEOUT, async {
            let mut first = [0];
            if stream.read(&mut first).await.map_err(ControlError::Io)? == 0 {
                return Ok(None);
            }
            let mut reader = first.as_slice().chain(&mut stream);
            Response::read(&mut reader).await.map(Some)
        })
        .await
        .map_err(|_| ControlError::Timeout {
            phase: "response read",
        })??;
        match response {
            None | Some(Response::Ack) => Ok(pid),
            Some(Response::Refused(reason)) => Err(ControlError::Refused(reason)),
            Some(Response::Error(reason)) => Err(ControlError::Protocol(reason)),
            Some(other) => Err(ControlError::Protocol(format!(
                "unexpected reply to stop: {other:?}"
            ))),
        }
    }

    /// One request, one response, one connection. Maps a wire `Refused`/`Error` to the typed error at
    /// the boundary so a caller can match it, never a stringified cause.
    async fn exchange(&self, request: &Request) -> Result<Response, ControlError> {
        let (stream, _) = self.connect().await?;
        Self::exchange_on(stream, request).await
    }

    /// One request/response exchange on an established stream under the phase bounds. Split from
    /// [`exchange`](Self::exchange) so tests can drive the write and read deadlines over an
    /// in-memory duplex a real request frame is too small to wedge.
    async fn exchange_on<S>(mut stream: S, request: &Request) -> Result<Response, ControlError>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        Self::write_request(&mut stream, request).await?;
        Self::read_response(&mut stream, request).await
    }

    // Keep write failure outside stop's read-EOF success rule.
    async fn write_request<S>(stream: &mut S, request: &Request) -> Result<(), ControlError>
    where
        S: tokio::io::AsyncWrite + Unpin,
    {
        timeout(IO_TIMEOUT, request.write(stream))
            .await
            .map_err(|_| ControlError::Timeout {
                phase: "request write",
            })?
            .map_err(ControlError::Io)
    }

    async fn read_response<S>(stream: &mut S, request: &Request) -> Result<Response, ControlError>
    where
        S: tokio::io::AsyncRead + Unpin,
    {
        // One deadline encloses the complete declared response, never each byte or field.
        timeout(IO_TIMEOUT, async {
            match request {
                Request::LocalServiceDetail => Response::read_local_detail(stream).await,
                _ => Response::read(stream).await,
            }
        })
        .await
        .map_err(|_| ControlError::Timeout {
            phase: "response read",
        })?
    }
}

impl NodeClient for UidSocket {
    async fn services(&self) -> Result<ServiceMenu, ControlError> {
        match self.exchange(&Request::Services).await? {
            Response::Catalog(menu) => Ok(menu),
            Response::Refused(reason) => Err(ControlError::Refused(reason)),
            Response::Error(reason) => Err(ControlError::Protocol(reason)),
            other => Err(ControlError::Protocol(format!(
                "unexpected reply to services: {other:?}"
            ))),
        }
    }

    async fn status(&self) -> Result<StatusReply, ControlError> {
        match self.exchange(&Request::Status).await? {
            Response::Status(status) => Ok(status),
            Response::Refused(reason) => Err(ControlError::Refused(reason)),
            Response::Error(reason) => Err(ControlError::Protocol(reason)),
            other => Err(ControlError::Protocol(format!(
                "unexpected reply to status: {other:?}"
            ))),
        }
    }

    async fn stop(&self) -> Result<(), ControlError> {
        self.stop_attributed().await.map(|_| ())
    }
}

/// A client for node control operations.
#[derive(Debug)]
pub enum ControlClient {
    /// The local resident's Unix socket client.
    Socket(UidSocket),
}

impl ControlClient {
    /// Resolve the local socket backend without connecting. Path resolution does not establish resident
    /// absence or identify the listener; each exchange checks the connected peer before sending a request.
    pub fn resolve(home: &Home) -> Result<Self, ControlError> {
        Ok(Self::Socket(UidSocket::resolve(home)?))
    }

    /// Construct a local backend from a socket path for tests. Production resolves the backend from the
    /// selected home.
    pub fn resolve_socket(home: &Home, socket: PathBuf) -> Result<Self, ControlError> {
        Ok(Self::Socket(UidSocket::resolve_socket(home, socket)?))
    }

    /// Read local startup targets through the socket backend only.
    ///
    /// This local-only operation is not part of [`NodeClient`].
    ///
    /// # Errors
    ///
    /// Returns the errors from [`UidSocket::local_service_detail`] without fallback or reclassification.
    pub async fn local_service_detail(&self) -> Result<LocalServiceSnapshot, ControlError> {
        match self {
            Self::Socket(socket) => socket.local_service_detail().await,
        }
    }

    /// Request a local stop and return the listener PID attributed by the socket backend on that
    /// exchange. After the complete request is written, success requires a complete acknowledgement or
    /// EOF before any response byte. Success does not prove that the process has exited.
    pub async fn stop_attributed(&self) -> Result<ProcessId, ControlError> {
        match self {
            Self::Socket(socket) => socket.stop_attributed().await,
        }
    }
}

impl NodeClient for ControlClient {
    async fn services(&self) -> Result<ServiceMenu, ControlError> {
        match self {
            Self::Socket(socket) => socket.services().await,
        }
    }

    async fn status(&self) -> Result<StatusReply, ControlError> {
        match self {
            Self::Socket(socket) => socket.status().await,
        }
    }

    async fn stop(&self) -> Result<(), ControlError> {
        match self {
            Self::Socket(socket) => socket.stop().await,
        }
    }
}

/// Render shared control failures for a command boundary.
///
/// This helper gives Protocol errors version-skew guidance. Local service detail reports its
/// protocol failures separately; its state, resource and peer failures are not version skew.
pub fn control_error_report(error: ControlError) -> eyre::Report {
    match error {
        ControlError::Protocol(reason) => eyre::eyre!(
            "the resident is a different swoosh version ({reason}); restart it with this binary"
        ),
        other => eyre::Report::new(other),
    }
}

/// The effective uid: the owner every control peer and runtime path must match.
pub(crate) fn euid() -> u32 {
    // SAFETY: `geteuid` takes no arguments and touches no memory.
    unsafe { libc::geteuid() }
}

#[derive(Debug)]
struct PeerCredentials {
    uid: u32,
    pid: ProcessId,
}

impl PeerCredentials {
    fn from_kernel(uid: u32, pid: libc::pid_t) -> io::Result<Self> {
        let pid = u32::try_from(pid)
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?
            .try_into()?;
        Ok(Self { uid, pid })
    }
}

// Query only the connected client fd. On macOS LOCAL_PEERPID names the listener;
// getpeereid supplies the UID independently. Neither pathname metadata nor a wire PID suffices.
fn real_peer_credentials(fd: i32) -> io::Result<PeerCredentials> {
    #[cfg(target_os = "macos")]
    {
        let uid = real_peer_uid(fd)?;
        let mut pid: libc::pid_t = 0;
        let mut len = core::mem::size_of_val(&pid) as libc::socklen_t;
        // SAFETY: fd is borrowed from a live connected stream; pid and len are valid
        // output slots of the size requested by LOCAL_PEERPID.
        let ok = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_LOCAL,
                libc::LOCAL_PEERPID,
                (&mut pid as *mut libc::pid_t).cast::<libc::c_void>(),
                &mut len,
            )
        };
        if ok != 0 {
            return Err(io::Error::last_os_error());
        }
        if len as usize != core::mem::size_of_val(&pid) {
            return Err(io::ErrorKind::InvalidData.into());
        }
        PeerCredentials::from_kernel(uid, pid)
    }
    #[cfg(target_os = "linux")]
    {
        // SAFETY: ucred is plain C integer data; zero initializes every output field.
        let mut cred: libc::ucred = unsafe { core::mem::zeroed() };
        let mut len = core::mem::size_of_val(&cred) as libc::socklen_t;
        // SAFETY: fd is a live connected stream; cred and len are valid output slots,
        // sized exactly for SO_PEERCRED. Check the returned length before accepting fields.
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
            return Err(io::Error::last_os_error());
        }
        if len as usize != core::mem::size_of_val(&cred) {
            return Err(io::ErrorKind::InvalidData.into());
        }
        PeerCredentials::from_kernel(cred.uid, cred.pid)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = fd;
        Err(io::ErrorKind::Unsupported.into())
    }
}

/// Read the uid of the peer connected on `fd`: macOS `getpeereid`, Linux `SO_PEERCRED`.
pub(crate) fn real_peer_uid(fd: i32) -> std::io::Result<u32> {
    #[cfg(target_os = "macos")]
    {
        let mut uid: libc::uid_t = 0;
        let mut gid: libc::gid_t = 0;
        // SAFETY: `fd` is the live fd of the connected stream (borrowed, still open for this call),
        // and `uid`/`gid` are valid stack slots for the out params.
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
        // SAFETY: `fd` is the live connected-stream fd; `cred`/`len` are valid out-param slots sized
        // exactly for `SO_PEERCRED`.
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

#[cfg(test)]
#[path = "node_client_tests.rs"]
mod node_client_tests;
