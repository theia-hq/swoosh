//! The one swoosh connect runner over tightbeam's tunnel [`Connector`], and the [`To`] sink selector it
//! is parameterized by.
//!
//! NOT a verb: `swoosh reach <peer> <service> [--to <port | - | unix:PATH>]` is the surface, and this is
//! the body it drives. The two halves are split because the act ("dial a peer's served service,
//! optionally presenting a cap, then drive it") is one thing while WHERE the bytes go is a choice the
//! caller makes: `Port` binds a local port and forwards each connection, `Stdout` streams the single
//! stream over this process's stdin/stdout, `UnixListener` is reserved. The present/badge
//! choice lives in exactly one place (the caller picks `present` before handing off).
//!
//! `swoosh ssh` reaches the same runner the same way, through the PUBLIC verb: its `ProxyCommand`
//! re-invokes THIS binary as `<self> reach <key> <service> --to -` via `current_exe()` (not a separate
//! `tightbeam` binary on PATH), so the bridge an operator debugs by hand is the one ssh runs.

use core::str::FromStr;
use std::io::Read as _;
use std::path::PathBuf;

use bifrost::{Discovery, Node, Session as _, Transport};
use nauthy::{Link, Service};
use swoosh::contacts::Contacts;
use swoosh::escape::escaped_report;
use swoosh::peer::Peer;
use tightbeam::tunnel::Connector;
use tokio::io::{self, AsyncWriteExt as _};
use tokio::sync::mpsc;

/// Where a reached service's bytes go locally: the one `--to` selector, parsed to a closed enum so the
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
            _ => eyre::bail!(
                "`{text}` is not a valid --to target. Use a port (1..=65535), `-` for stdout (compose \
                 with the shell, e.g. `--to - > out`), or `unix:<path>` for a local socket listener"
            ),
        }
    }
}

/// The ONE connect path, driven by `reach` directly and by `swoosh ssh` through it. Resolve the [`Peer`]
/// to a connector via the shared [`Peer::connector`] (slot 1 the grant, slot 2 a membership badge for a
/// signet-bound slip's AND), then drive the sink [`To`] names: forward a local port (proving admission,
/// then printing swoosh's own `forwarding …` line), stream stdin/stdout (no banner: ssh owns the tty), or
/// the reserved unix listener. A refused forward surfaces the host's reason here and exits non-zero,
/// never a fake banner.
pub async fn connect<T: Transport, D: Discovery>(
    node: &Node<T, D>,
    contacts: &Contacts,
    peer: &Peer,
    service: Service,
    slot1: Option<Link>,
    slot2: Option<Link>,
    to: To,
) -> eyre::Result<()> {
    let connector = peer.connector(contacts, service, slot1, slot2)?;
    match to {
        To::Port(port) => {
            // Prove the gate admits us BEFORE printing "forwarding …": `preflight` reaches, probes
            // admission on one stream, and binds the port, returning the host's refusal reason on an
            // Err. So an unauthorized forward fails loudly here (a clear one-line reason, non-zero exit),
            // never a hopeful banner followed by a silent reset.
            let (dial, service) = (connector.dial(), Service::clone(connector.service()));
            let forward = connector
                .preflight(node, port)
                .await
                .map_err(escaped_report)?;
            println!("forwarding 127.0.0.1:{port} to {dial} ({service})");
            forward.run().await
        }
        To::Stdout => pipe_stdio(connector, node).await.map_err(escaped_report),
        To::UnixListener(path) => eyre::bail!(
            "--to unix:{} is reserved, not yet built (bind a port and connect to it, or use `--to -`)",
            path.display()
        ),
    }
}

/// Reach the service over one stream and pipe it against this process's stdin and stdout: the bridge
/// `swoosh ssh` runs as its `ProxyCommand`.
///
/// The pump ends on the host's half: when the stream from the host ends or errors (the remote command
/// exited, or the host cut the session on a revoke or an expiry), the run is over, whatever stdin is
/// doing. stdin is read on its own thread (see [`stdin_chunks`]), so nothing waits on a read that, at a
/// terminal or under ssh, only returns when the person types again.
async fn pipe_stdio<T: Transport, D: Discovery>(
    connector: Connector,
    node: &Node<T, D>,
) -> eyre::Result<()> {
    // Held for the whole pump: the stream rides this session, which closes when it drops.
    let session = connector.open_service(node).await?;
    let (mut writer, mut reader) = session.open_bi().await?;
    let mut input = stdin_chunks()?;
    let mut output = io::stdout();
    let upstream = async {
        while let Some(chunk) = input.recv().await {
            writer.write_all(&chunk?).await?;
        }
        writer.shutdown().await
    };
    let downstream = async {
        io::copy(&mut reader, &mut output).await?;
        output.flush().await
    };
    tokio::select! {
        // The host's half ended or failed: the run is over. The stdin pump is dropped, never awaited.
        result = downstream => result?,
        // stdin ended first (a piped, finite input), or the write toward the host failed. A clean end
        // half-closes toward the host, then the host's remaining output still drains to stdout.
        result = upstream => {
            result?;
            io::copy(&mut reader, &mut output).await?;
            output.flush().await?;
        }
    }
    Ok(())
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
    use swoosh::contacts::Contacts;
    use swoosh::testkit::HostilePeer;

    use super::{To, connect};

    /// A gate's refusal detail holding a carriage return, an ESC CSI sequence and a bidi override.
    const HOSTILE: &str = "no\r\u{1b}[2Kforwarding 127.0.0.1:1 to x\u{202e}";
    /// [`HOSTILE`] as it prints.
    const ESCAPED: &str = r"no\r\u{1b}[2Kforwarding 127.0.0.1:1 to x\u{202e}";

    /// Reach a peer whose gate refuses with [`HOSTILE`], sinking the bytes into `to`.
    async fn refused(to: To) -> eyre::Report {
        let node = bifrost::Node::new(HostilePeer::RefusesAtTheGate(HOSTILE), bifrost::NoDiscovery);
        let peer = HostilePeer::node_id()
            .to_string()
            .parse()
            .expect("a raw key parses as a Peer");
        let service = "db".parse().expect("db is a service name");
        connect(&node, &Contacts::default(), &peer, service, None, None, to)
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

    // The stdio bridge (`--to -`, and `swoosh ssh`'s ProxyCommand through it) prints the same refusal the
    // same way.
    #[tokio::test]
    async fn a_hostile_stdio_refusal_prints_escaped() {
        let error = refused(To::Stdout).await;
        assert_eq!(
            format!("{error:#}"),
            format!("stream refused: unavailable: {ESCAPED}")
        );
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
    }
}
