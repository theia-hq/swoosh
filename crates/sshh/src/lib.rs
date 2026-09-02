//! `sshh`: a keyless SSH server over an already-authenticated byte stream.
//!
//! theia's equivalent of Tailscale SSH. The caller hands [`serve`] one stream that a capability-gated
//! overlay has ALREADY mutually authenticated (QUIC + raw-public-key TLS, addressed by ed25519 node id)
//! and encrypted; the peer was authorized by a capability. So SSH's own transport job is already done, and
//! this server accepts the SSH `none` auth method (russh's default) and goes straight to a shell: the
//! capability IS the auth, exactly as Tailscale SSH accepts `none` behind WireGuard. A standard `ssh`/`scp`
//! client works unchanged, with no ssh keys to manage.
//!
//! This lives in its own crate, apart from the byte-funnel (tightbeam), so its heavy, security-sensitive
//! dependency tree (`russh`, `ssh-key`, `pty-process`) never weighs down a tunnel binary.
//!
//! SAFETY: a shell has no auth of its own, so the caller MUST only ever hand [`serve`] a stream that a real
//! gate already admitted (never a raw socket, never an `open` gate). As a second line of defence, [`serve`]
//! refuses to run as root, since a cap-holder would otherwise get a root shell.
//!
//! NOT YET (tracked follow-ups from the Tailscale-parity study): SFTP/scp, and per-user mapping (today
//! the shell runs as this process's uid).

use core::sync::atomic::{AtomicUsize, Ordering};

use tokio::io::{self, AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::sync::watch;

use pty_process::{Command, Size};
use russh::server::{Handler, Msg, Session};
use russh::{Channel, ChannelId};

/// The maximum number of concurrent shells this process serves across ALL connections. A shell has no
/// login of its own, so an admitted peer (or a leaked slip) could otherwise open unbounded channels and
/// connections and fork-bomb the host, running arbitrary code as this uid. Past this cap a new shell
/// request is refused (`channel_failure`); the ceiling is generous for real interactive/exec use and
/// bounded against abuse. Node-wide, not per-connection, because a flood opens many connections.
const MAX_LIVE_SHELLS: usize = 64;

/// Live shell count across the whole process, reserved by [`ShellSlot`].
static LIVE_SHELLS: AtomicUsize = AtomicUsize::new(0);

/// An RAII reservation of one concurrent-shell slot. Held for the shell's whole lifetime (moved into the
/// serving task) and released on drop (including every early return before the task is spawned), so the
/// count can never leak a slot and wedge the cap shut.
struct ShellSlot;

impl ShellSlot {
    /// Reserve a slot, or `None` if the process is already at [`MAX_LIVE_SHELLS`]. The reserve-then-check
    /// (fetch_add, roll back if over) is race-free under concurrent connections.
    fn acquire() -> Option<Self> {
        if LIVE_SHELLS.fetch_add(1, Ordering::AcqRel) >= MAX_LIVE_SHELLS {
            LIVE_SHELLS.fetch_sub(1, Ordering::AcqRel);
            None
        } else {
            Some(ShellSlot)
        }
    }
}

impl Drop for ShellSlot {
    fn drop(&mut self) {
        LIVE_SHELLS.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Serving one SSH connection failed.
#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    /// Refused to serve a shell as root (a cap-holder would get a root shell).
    #[error("refusing to serve a shell as root; run the ssh server as an unprivileged user")]
    Root,
    /// The SSH handshake over the stream failed.
    #[error("ssh handshake")]
    Handshake(#[source] russh::Error),
    /// The SSH session failed after the handshake.
    #[error("ssh session")]
    Session(#[source] russh::Error),
}

/// Derive a node's stable SSH host-key seed from its raw identity secret.
///
/// A keyless shell still presents a host key so a client's `known_hosts` can pin the node across
/// connections (trust-on-first-use, with a later swap detected). That key must be STABLE across runs yet
/// DISTINCT from the node's identity key (no cross-protocol reuse), so it is a domain-separated derivation
/// (BLAKE3 `derive_key`) of the raw secret. The caller derives the seed once from its persisted identity and
/// hands it to [`serve`]; the raw secret itself never enters this crate.
///
/// The domain-separator string is FROZEN: a client pins the resulting host key, so changing it would break
/// every existing `known_hosts` entry.
pub fn host_seed(secret: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key("theia sshh host key v1", secret)
}

/// Run one SSH connection over an already-authenticated, cap-gated stream: accept `none` auth and serve a
/// pty shell. Returns when the client disconnects or the shell exits.
///
/// CONSUMES a [`nauthy::Admitted`] witness by value: a keyless shell accepting `none` auth is safe ONLY
/// behind a gate, so requiring the gate's un-forgeable proof makes "authorize before serve" a compile-time
/// precondition, not a caller's discipline. Taking it by value (and `Admitted` being neither `Copy` nor
/// `Clone`) makes the witness single-use: one admit authorizes exactly one `serve`, so a caller cannot
/// replay one witness onto a second stream. The witness is not otherwise inspected.
///
/// Refuses to run as root by construction: a shell served to a cap-holder runs as this process's user, so
/// running privileged would hand every cap-holder a root shell. Run the server unprivileged.
pub async fn serve<W, R>(
    _admitted: nauthy::Admitted,
    host_seed: [u8; 32],
    writer: W,
    reader: R,
) -> Result<(), ServeError>
where
    W: AsyncWrite + Unpin + Send + 'static,
    R: AsyncRead + Unpin + Send + 'static,
{
    if is_root() {
        return Err(ServeError::Root);
    }
    // The host key is derived by the caller from the node identity, so it is STABLE across connections:
    // `known_hosts` pins the node you dial instead of a fresh key each time (which trained users to click
    // through host-key warnings). It is not the auth (the overlay already authenticated) but host
    // self-consistency, so a client trusts-on-first-use and detects a later swap.
    let key = ssh_key::PrivateKey::from(ssh_key::private::Ed25519Keypair::from_seed(&host_seed));
    let config = std::sync::Arc::new(russh::server::Config {
        keys: vec![key],
        // Offer ONLY `none` auth: the overlay already authenticated the peer, so ssh must not demand a
        // second credential. Without this russh advertises publickey/password and the client, having no
        // key, is refused before it ever reaches `none`.
        methods: russh::MethodSet::from(&[russh::MethodKind::None][..]),
        ..Default::default()
    });
    // Join the two stream halves into one duplex for russh, then run the SSH session to completion.
    let stream = tokio::io::join(reader, writer);
    let running = russh::server::run_stream(config, stream, Shell::default())
        .await
        .map_err(ServeError::Handshake)?;
    // russh spawns the SSH session on a DETACHED task the moment `run_stream` returns Ok; `running.await`
    // only OBSERVES its completion, it does not drive it. So cancelling `serve` (dropping this future) does
    // not abort an in-flight shell, it only stops us awaiting it: the shell runs until the client
    // disconnects or exits. Not a leak (the shell is bounded by the caller's live-session cap), but the
    // reason a session cannot be torn down mid-flight by dropping `serve`.
    running.await.map_err(ServeError::Session)?;
    Ok(())
}

/// Per-connection handler: hold the opened session channel and the requested pty geometry, then on a
/// shell/exec request spawn the shell in a pty and splice the channel to it. Auth is not implemented, so
/// russh's default `auth_none` (accept) stands: the overlay already proved the peer.
#[derive(Default)]
struct Shell {
    channel: Option<Channel<Msg>>,
    term: String,
    cols: u16,
    rows: u16,
    /// Live resize handle into the running splice task, `Some` only after [`Shell::spawn`]. A
    /// `window_change_request` pushes the new [`Size`] through this so the task (sole owner of the pty)
    /// applies it; the pty is never shared. `None` before the shell spawns, so a window-change that
    /// arrives first is captured into `cols`/`rows` and used as the initial size instead.
    resize: Option<watch::Sender<Size>>,
}

impl Shell {
    /// Spawn the shell (a login shell, or `sh -c <command>` for exec) in a pty at the requested size and
    /// splice the ssh channel to it, on its own task so the handler stays responsive.
    fn spawn(
        &mut self,
        id: ChannelId,
        command: Option<String>,
        session: &mut Session,
    ) -> Result<(), russh::Error> {
        let Some(mut channel) = self.channel.take() else {
            let _ = session.channel_failure(id);
            return Ok(());
        };
        // Reserve a concurrent-shell slot BEFORE opening a pty or spawning: at the node's cap, refuse
        // rather than let a flood exhaust the host. The slot releases on any early return below, and is
        // moved into the serving task so it lives exactly as long as the shell.
        let Some(slot) = ShellSlot::acquire() else {
            let _ = session.channel_failure(id);
            return Ok(());
        };
        let (pty, pts) = match pty_process::open() {
            Ok(pair) => pair,
            Err(_) => {
                let _ = session.channel_failure(id);
                return Ok(());
            }
        };
        // The latest geometry the client asked for, from `pty_request` and any `window_change_request`
        // that landed before the shell spawned. Seed the pty and the resize channel with it.
        let size = win_size(self.cols, self.rows);
        if pty.resize(size).is_err() {
            let _ = session.channel_failure(id);
            return Ok(());
        }
        // The splice task owns the pty; a later `window_change_request` pushes a new size through this
        // sender and the task applies it. Keep the sender on `self` so the `&mut self` handler can send.
        let (resize_tx, resize_rx) = watch::channel(size);
        self.resize = Some(resize_tx);
        let term = if self.term.is_empty() {
            "xterm-256color"
        } else {
            &self.term
        };
        let cmd = match &command {
            Some(command) => Command::new("/bin/sh").arg("-c").arg(command),
            None => Command::new(login_shell()),
        }
        .env("TERM", term);
        let child = match cmd.spawn(pts) {
            Ok(child) => child,
            Err(_) => {
                let _ = session.channel_failure(id);
                return Ok(());
            }
        };
        let handle = session.handle();
        session.channel_success(id)?;
        tokio::spawn(async move {
            // Hold the shell slot for the child's whole lifetime; it releases when this task ends.
            let _slot = slot;
            // Splice the ssh channel to the pty: channel input -> shell, shell output -> channel. Take the
            // `'static` writer before the borrowing reader.
            let writer = channel.make_writer();
            let reader = channel.make_reader();
            let _ = splice(pty, writer, reader, resize_rx).await;
            // Report the shell's exit and close the channel so the client's `ssh` exits cleanly.
            let code = wait_code(child).await;
            let _ = handle.exit_status_request(id, code).await;
            let _ = handle.eof(id).await;
            let _ = handle.close(id).await;
        });
        Ok(())
    }
}

impl Handler for Shell {
    type Error = russh::Error;

    /// Accept `none` auth: the cap-gated overlay already authenticated the peer, so ssh owes no second
    /// credential. russh's default rejects `none`, so this override is what makes sshh keyless.
    async fn auth_none(&mut self, _user: &str) -> Result<russh::server::Auth, Self::Error> {
        Ok(russh::server::Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channel = Some(channel);
        reply.accept().await;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn pty_request(
        &mut self,
        id: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.term = term.to_owned();
        self.cols = col_width as u16;
        self.rows = row_height as u16;
        session.channel_success(id)?;
        Ok(())
    }

    /// Propagate a live terminal resize to the running pty, so full-screen apps (vim, htop, less) reflow
    /// instead of rendering at the old geometry. OpenSSH sends this on the client's SIGWINCH.
    ///
    /// Two orderings, both handled: AFTER the shell spawned, push the new size to the splice task (sole
    /// owner of the pty) via the resize channel; a send error means the shell already exited, so drop it.
    /// BEFORE the shell spawned (no task yet), record the geometry so [`Shell::spawn`] opens the pty at
    /// the up-to-date size instead of a stale one.
    #[allow(clippy::too_many_arguments)]
    async fn window_change_request(
        &mut self,
        id: ChannelId,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.cols = col_width as u16;
        self.rows = row_height as u16;
        if let Some(resize) = &self.resize {
            let _ = resize.send(win_size(self.cols, self.rows));
        }
        session.channel_success(id)?;
        Ok(())
    }

    async fn shell_request(
        &mut self,
        id: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.spawn(id, None, session)
    }

    async fn exec_request(
        &mut self,
        id: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let command = String::from_utf8_lossy(data).into_owned();
        self.spawn(id, Some(command), session)
    }
}

/// Copy bytes both ways between the pty and the ssh channel until both sides close, applying any
/// terminal resize that arrives on `resize` to the pty along the way.
///
/// Owns the pty by value and splits it into the two directions with `into_split`, so the pty stays
/// single-owned by this task: resizes come in over the channel and are applied on the write half's own
/// `resize`, sidestepping any shared `Pty` handle. The write direction is a manual select loop (not a
/// plain `io::copy`) precisely so it can also poll the resize receiver; each arm is a whole await with no
/// half-read held across it, so cancelling one to run the other loses no bytes.
async fn splice<W, R>(
    local: pty_process::Pty,
    mut writer: W,
    mut reader: R,
    mut resize: watch::Receiver<Size>,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    let (mut local_reader, mut local_writer) = local.into_split();
    let upstream = async {
        io::copy(&mut local_reader, &mut writer).await?;
        writer.shutdown().await
    };
    let downstream = async {
        let mut buf = [0u8; 8 * 1024];
        loop {
            tokio::select! {
                // `biased` so a pending resize is applied before more input bytes are pumped, keeping the
                // pty geometry current for the data that follows.
                biased;
                // A new terminal size: apply it to the pty. A resize failing is non-fatal (the pty may be
                // tearing down), so log nothing and keep splicing.
                changed = resize.changed() => match changed {
                    // `borrow_and_update` marks the value seen, so the next `changed()` waits for the next
                    // send rather than re-firing on this one.
                    Ok(()) => {
                        let _ = local_writer.resize(*resize.borrow_and_update());
                    }
                    // The sender dropped (the handler is gone), so no more resizes will ever come. A closed
                    // watch resolves `changed()` immediately, which would busy-spin this arm, so copy the
                    // rest of the input with a plain `io::copy` and finish.
                    Err(_) => {
                        io::copy(&mut reader, &mut local_writer).await?;
                        break;
                    }
                },
                read = reader.read(&mut buf) => match read? {
                    // Channel EOF: the client closed its input, so half-close the pty and finish.
                    0 => break,
                    n => local_writer.write_all(&buf[..n]).await?,
                },
            }
        }
        local_writer.shutdown().await
    };
    tokio::try_join!(upstream, downstream)?;
    Ok(())
}

/// Map an SSH window geometry (columns, rows) to a pty [`Size`], clamped to at least 1x1. A client can
/// send a zero dimension (or none at all, defaulting the fields to 0); a 0-row/0-col pty is degenerate and
/// makes full-screen apps misrender, so floor each at 1, mirroring the initial-size clamp.
fn win_size(cols: u16, rows: u16) -> Size {
    let (rows, cols) = clamp_geometry(cols, rows);
    Size::new(rows, cols)
}

/// Floor a client (cols, rows) geometry at 1x1 and return it as (rows, cols), the order [`Size::new`]
/// takes. Split out from [`win_size`] as the testable seam, since [`Size`] exposes no field accessors.
fn clamp_geometry(cols: u16, rows: u16) -> (u16, u16) {
    (rows.max(1), cols.max(1))
}

/// This user's login shell for a bare `shell` request: `$SHELL` if set, else a sane default.
fn login_shell() -> String {
    std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_owned())
}

/// Wait for the shell to exit and map its status to an SSH exit code (0 if killed by a signal).
async fn wait_code(mut child: tokio::process::Child) -> u32 {
    child
        .wait()
        .await
        .ok()
        .and_then(|status| status.code())
        .unwrap_or(0) as u32
}

/// Whether this process runs as the superuser. A shell served here runs as this uid, so root is refused.
fn is_root() -> bool {
    #[cfg(unix)]
    {
        // SAFETY: getuid/geteuid always succeed; they read the process's uids and cannot fail. Check both
        // the real and effective uid, so neither a root real-uid nor an euid-0 process serves a shell.
        unsafe { libc::geteuid() == 0 || libc::getuid() == 0 }
    }
    #[cfg(not(unix))]
    {
        false
    }
}

#[cfg(test)]
#[path = "lib_tests.rs"]
mod lib_tests;
