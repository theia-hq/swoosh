//! The one swoosh connect runner over tightbeam's tunnel [`Connector`], plus the hidden `tunnel-connect`
//! leaf behind `swoosh ssh`.
//!
//! Both of swoosh's connect surfaces -- the public `forward <peer> --to <port | - | unix:PATH>`
//! (port-forward or stdout) and this hidden `tunnel-connect --to -` (the `swoosh ssh` ProxyCommand bridge)
//! -- are the SAME concept: dial a peer's served service, optionally presenting a cap, then drive it. They
//! differ only in surface (a user verb vs an ABI ssh re-invokes) and in how the sink is chosen. So they
//! share ONE [`connect`] runner over the library `Connector`, parameterized by the single [`To`] selector:
//! `Port` binds a local port and forwards each connection, `Stdout` streams the single stream over this
//! process's stdin/stdout, `UnixListener` is reserved. The present/self-signed-badge choice lives in
//! exactly one place (the caller picks `present` before handing off).
//!
//! The hidden leaf is not a user verb: it is the executable `swoosh ssh` names in ssh's `ProxyCommand`,
//! invoked on THIS binary via `current_exe()` (not a separate `tightbeam` binary on PATH). It binds a node
//! under swoosh's OWN identity, so a membership badge presented here binds to the identity the far family
//! gate will actually prove, and the whole flow stays one binary, one identity, no `$PATH` lookup.

use core::str::FromStr;
use std::path::PathBuf;

use bifrost::{Discovery, Node, NodeId, Transport};
use clap::Args;
use nauthy::{Cap, SCHEME};
use tightbeam::tunnel::Connector;

use crate::transport;

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

/// What swoosh's connect was pointed at: a bare node id, or a `sheer:` capability link. swoosh's OWN target
/// type, so its `forward`/ssh-bridge modules never name tightbeam's CLI-layer parse type. A link supersedes the
/// identity path: it names the node to dial (the cap's root) and presents the token; a bare node id is the
/// pre-capability path, gated on the proven identity alone.
#[derive(Debug, Clone)]
pub enum Dial {
    /// A raw node id to dial; the host gates on the proven identity.
    Node(NodeId),
    /// A `sheer:` capability link to present to a cap-gated host.
    Capability(String),
}

impl FromStr for Dial {
    type Err = eyre::Error;

    fn from_str(text: &str) -> eyre::Result<Self> {
        if text.starts_with(SCHEME) {
            // Parse it now so a malformed link fails fast at the CLI boundary, not mid-connect. The owned
            // string is re-parsed at use so the token travels whole to the host.
            Cap::parse(text)?;
            Ok(Dial::Capability(text.to_owned()))
        } else {
            Ok(Dial::Node(text.parse::<NodeId>()?))
        }
    }
}

/// Resolve the target into a [`Connector`]: a raw node id (optionally presenting a link) or a link that
/// supplies both the node to dial and the token.
fn connector(dial: &Dial, service: String, present: Option<String>) -> eyre::Result<Connector> {
    match dial {
        Dial::Node(id) => Ok(Connector::to_node(*id, service, present)),
        Dial::Capability(link) => Connector::from_link(link, service),
    }
}

/// The ONE connect path both swoosh surfaces drive. Resolve the connector, then drive the sink [`To`] names:
/// forward a local port (proving admission, then printing swoosh's own `forwarding …` line), stream
/// stdin/stdout (no banner: ssh owns the tty), or the reserved unix listener. A refused forward surfaces the
/// host's reason here and exits non-zero, never a fake banner.
pub async fn connect<T: Transport, D: Discovery>(
    node: &Node<T, D>,
    dial: Dial,
    service: String,
    present: Option<String>,
    to: To,
) -> eyre::Result<()> {
    let connector = connector(&dial, service, present)?;
    match to {
        To::Port(port) => {
            // Prove the gate admits us BEFORE printing "forwarding …": `preflight` reaches, probes
            // admission on one stream, and binds the port, returning the host's refusal reason on an
            // Err. So an unauthorized forward fails loudly here (a clear one-line reason, non-zero exit),
            // never a hopeful banner followed by a silent reset.
            let (dial, service) = (connector.dial(), connector.service().to_owned());
            let forward = connector.preflight(node, port).await?;
            println!("forwarding 127.0.0.1:{port} to {dial} ({service})");
            forward.run().await
        }
        To::Stdout => connector.pipe_stdio(node).await,
        To::UnixListener(path) => eyre::bail!(
            "--to unix:{} is reserved, not yet built (bind a port and connect to it, or use `--to -`)",
            path.display()
        ),
    }
}

/// Stream a peer's exposed service over stdin/stdout (the ssh `ProxyCommand` bridge). Hidden: reached only
/// through `swoosh ssh`, never typed by a user.
#[derive(Debug, Args)]
pub struct TunnelConnectCmd {
    /// the peer to reach, a raw node id already resolved by `swoosh ssh`
    #[arg(value_name = "peer")]
    pub node: NodeId,
    /// the exposed service name to reach on the host
    #[arg(long, value_name = "service", default_value = "default")]
    pub service: String,
    /// present a membership badge or capability link to a family/cap-gated host
    #[arg(long, value_name = "link")]
    pub present: Option<String>,
    /// where to put the stream: the `swoosh ssh` ProxyCommand ABI always passes `-` (stdout). Accepted as
    /// the shared `--to` selector so the bridge speaks the same flag as `forward`; hidden, never typed.
    #[arg(long, value_name = "port | - | unix:PATH", hide = true)]
    pub to: To,
    #[command(flatten)]
    pub reach: transport::ReachArgs,
}

impl crate::reaching::Reaching for TunnelConnectCmd {
    fn reach_args(&self) -> &crate::transport::ReachArgs {
        &self.reach
    }

    /// `tunnel-connect` (the `swoosh ssh` bridge) reaches a family-gated host, so it presents the member
    /// badge rooted at the dialing key. It binds `Persisted` for a different reason (dialing under
    /// swoosh's OWN key so the gate proves the identity the badge was minted for): a non-forgettable
    /// override, applied in the composition root, not this derivation.
    fn credential(&self) -> crate::credential::Credential {
        crate::credential::Credential::Family { present: None }
    }

    /// `tunnel-connect` MUST dial under swoosh's OWN persisted key so the family gate proves the identity
    /// the membership badge was minted for, so it declares `Persisted` EXPLICITLY rather than inheriting
    /// the credential's derived `PersistedIfPresent`. A written declaration the compiler requires.
    fn identity(&self) -> crate::identity::Identity {
        crate::identity::Identity::Persisted
    }
}

impl TunnelConnectCmd {
    /// Stream the peer's service against this process's stdin/stdout, dialing under swoosh's own identity.
    /// Always `--to -` in practice: this leaf exists only as the ssh `ProxyCommand` bridge.
    ///
    /// The badge presented to a family-gated host is an explicit `--present` link if given, else the
    /// `self_signed` badge the caller minted from this identity (the signet holder is entitled to sign its
    /// own, fresh per dial). A node gated Open ignores whatever is presented, so presenting is always safe.
    /// This is the one place the two connect surfaces differ in how `present` is chosen.
    pub async fn run<T: Transport, D: Discovery>(
        self,
        node: &Node<T, D>,
        self_signed: Option<String>,
    ) -> eyre::Result<()> {
        let present = self.present.or(self_signed);
        connect(node, Dial::Node(self.node), self.service, present, self.to).await
    }
}

#[cfg(test)]
mod tests {
    use super::To;

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
