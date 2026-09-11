//! The control surface every node backend serves: one trait, a typed shared error, two backends.
//!
//! The uid-socket client and the resident itself implement [`NodeClient`], so a behavior change lands
//! once and both stay in step. The verbs (bare control) reach a node through [`ControlClient`], which
//! today has exactly one arm, the local socket; the overlay joins as a second arm in a later phase and
//! is closed out of any local-only operation by construction. The SWC1 value types live in
//! [`crate::commands::serve::control`]; this module imports them and adds behavior only, so the module
//! graph stays a one-way edge from the client seam to the codec.

use core::future::Future;
use core::time::Duration;
use std::io;
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _};
use std::os::unix::io::AsRawFd as _;
use std::path::{Path, PathBuf};

use tokio::net::UnixStream;
use tokio::time::timeout;

use crate::commands::serve::control_codec::{
    ControlError, Request, Response, ServiceMenu, StatusReply,
};
use crate::home::Home;

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
    /// Ask the node to stop gracefully. The resident's stop is uid-equivalent to the SIGTERM the local
    /// user already holds.
    fn stop(&self) -> impl Future<Output = Result<(), ControlError>>;
}

/// The Phase 2 backend: the local resident's uid-gated control socket. One-shot SWC1 exchange per
/// call; holds no daemon handle and no shared state.
#[derive(Debug)]
pub struct UidSocket {
    /// The verified control socket path.
    socket: PathBuf,
    /// The resident pid read from `control.lock` at resolve, for the stop confirmation line.
    pid: Option<u32>,
}

impl UidSocket {
    /// Resolve and verify the socket for `home`. Never connects: a plain stat of the leaf dir and the
    /// socket is enough to separate a trusted local resident from a missing or planted one.
    pub fn resolve(home: &Home) -> Result<Self, ControlError> {
        // No addressable runtime root (XDG_RUNTIME_DIR unset or relative, confstr failed) means no
        // resident is addressable under this home, not an insecure path.
        let socket = home
            .control_socket()
            .map_err(|_| ControlError::NoResident)?;
        Self::resolve_socket(socket)
    }

    /// Verify an already-derived socket path (the path half of [`resolve`](Self::resolve)), split out
    /// so tests can drive the ownership/mode/socket checks without resolving a process-global runtime
    /// root. Never connects.
    fn resolve_socket(socket: PathBuf) -> Result<Self, ControlError> {
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
            || dir_meta.uid() != euid()
            || dir_meta.permissions().mode() & 0o777 != 0o700
        {
            return Err(ControlError::Untrusted { path: dir });
        }
        // Step 2: the socket must be a socket owned by this user. ENOENT is NoResident; a non-socket
        // inode, a foreign owner, or a stat failure is Untrusted.
        match std::fs::symlink_metadata(&socket) {
            Ok(meta) if meta.file_type().is_socket() && meta.uid() == euid() => {}
            Ok(_) => return Err(ControlError::Untrusted { path: socket }),
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {
                return Err(ControlError::NoResident);
            }
            Err(_) => return Err(ControlError::Untrusted { path: socket }),
        }
        let pid = read_lock_pid(&socket.with_file_name("control.lock"));
        Ok(Self { socket, pid })
    }

    /// Dial the verified socket and prove the CONNECTED peer's uid is ours. The path stat in
    /// [`resolve`](Self::resolve) can race a same-uid swap; a connected fd cannot, so this is the
    /// client-side twin of the server's accepted-fd check.
    async fn connect(&self) -> Result<UnixStream, ControlError> {
        let stream = timeout(CONNECT_TIMEOUT, UnixStream::connect(&self.socket))
            .await
            .map_err(|_| ControlError::Timeout { phase: "connect" })?
            .map_err(|error| match error.raw_os_error() {
                // The resident is gone (crash plant or never bound): a typed miss, not an I/O error.
                Some(libc::ENOENT | libc::ECONNREFUSED) => ControlError::NoResident,
                _ => ControlError::Io(error),
            })?;
        let uid = real_peer_uid(stream.as_raw_fd()).map_err(|_| ControlError::Untrusted {
            path: self.socket.clone(),
        })?;
        if uid != euid() {
            return Err(ControlError::Untrusted {
                path: self.socket.clone(),
            });
        }
        Ok(stream)
    }

    /// One request, one response, one connection. Maps a wire `Refused`/`Error` to the typed error at
    /// the boundary so a caller can match it, never a stringified cause.
    async fn exchange(&self, request: &Request) -> Result<Response, ControlError> {
        let mut stream = self.connect().await?;
        timeout(IO_TIMEOUT, request.write(&mut stream))
            .await
            .map_err(|_| ControlError::Timeout {
                phase: "request write",
            })?
            .map_err(ControlError::Io)?;
        timeout(IO_TIMEOUT, Response::read(&mut stream))
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
        match self.exchange(&Request::Stop).await {
            Ok(Response::Ack) => Ok(()),
            Ok(Response::Refused(reason)) => Err(ControlError::Refused(reason)),
            Ok(Response::Error(reason)) => Err(ControlError::Protocol(reason)),
            Ok(other) => Err(ControlError::Protocol(format!(
                "unexpected reply to stop: {other:?}"
            ))),
            // A clean EOF after the request was written is a success: the resident may cancel its
            // accept loop between writing the Ack and our read, the same discipline the wire stop
            // uses. Any other I/O error stays loud.
            Err(ControlError::Io(error)) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(()),
            Err(error) => Err(error),
        }
    }
}

/// The pluggable client backends, chosen by distance. Phase 2 builds one arm; the enum is the slot,
/// because the overlay joins as a variant and the local socket is the only arm that can be resolved
/// for a same-machine call.
#[derive(Debug)]
pub enum ControlClient {
    /// The local resident's uid-gated socket. The only arm Phase 2 can construct.
    Socket(UidSocket),
}

impl ControlClient {
    /// Resolve the backend for a same-machine control call: the verified local socket, `NoResident`
    /// when no addressable resident exists, `Untrusted` when the path exists but is not this user's
    /// 0700 socket. Never attempts a connection.
    pub fn resolve(home: &Home) -> Result<Self, ControlError> {
        Ok(Self::Socket(UidSocket::resolve(home)?))
    }

    /// The resident pid read from `control.lock` at resolve, for the stop confirmation line.
    pub fn pid(&self) -> Option<u32> {
        match self {
            Self::Socket(socket) => socket.pid,
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

/// The most bytes [`read_lock_pid`] reads: a u32 pid is at most ten digits plus a newline, so sixteen
/// covers the record with room to spare.
const LOCK_PID_READ_CAP: u64 = 16;

/// Read the pid recorded in the control lock at `path`, if any. Bounded, so a same-uid process cannot
/// make a reader allocate on demand; absent or unparsable is `None`. The daemon start records this
/// pid, and both the single-instance refusal and the client stop line read it through here.
pub(crate) fn read_lock_pid(path: &Path) -> Option<u32> {
    use std::io::Read as _;

    let file = std::fs::File::open(path).ok()?;
    let mut reader = file.take(LOCK_PID_READ_CAP);
    let mut text = String::new();
    reader.read_to_string(&mut text).ok()?;
    text.split_whitespace().next()?.parse().ok()
}

/// The effective uid: the owner every control peer and runtime path must match.
pub(crate) fn euid() -> u32 {
    // SAFETY: `geteuid` takes no arguments and touches no memory.
    unsafe { libc::geteuid() }
}

/// Read the uid of the peer connected on `fd`: macOS `getpeereid`, Linux `SO_PEERCRED`. Shared by the
/// server's accepted-fd check and the client's connected-fd check so there is one implementation.
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
