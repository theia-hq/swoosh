//! The one swoosh connect runner over tightbeam's tunnel [`Connector`], plus the hidden `tunnel-connect`
//! leaf behind `swoosh ssh`.
//!
//! Both of swoosh's connect surfaces -- the public `reach <peer> <service> [--to <port | - | unix:PATH>]`
//! (stdout or port-forward) and this hidden `tunnel-connect --to -` (the `swoosh ssh` ProxyCommand bridge)
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
use nauthy::{Link, Service};
use swoosh::contacts::Contacts;
use swoosh::peer::Peer;
use swoosh::transport;
use swoosh::unbound::Unbound;

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

/// The ONE connect path both swoosh surfaces drive. Resolve the [`Peer`] to a connector via the shared
/// [`Peer::connector`] (slot 1 the grant, slot 2 a membership badge for a signet-bound slip's AND), then
/// drive the sink [`To`] names: forward a local port (proving admission, then printing swoosh's own
/// `forwarding …` line), stream stdin/stdout (no banner: ssh owns the tty), or the reserved unix listener.
/// A refused forward surfaces the host's reason here and exits non-zero, never a fake banner.
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
    // The name we are about to REQUEST, read off the connector before it is consumed. Everything the
    // refusal path says about serving comes from this string and nothing else.
    let requested = connector.service().as_str().to_owned();
    let reached = match to {
        To::Port(port) => {
            // Prove the gate admits us BEFORE printing "forwarding …": `preflight` reaches, probes
            // admission on one stream, and binds the port, returning the host's refusal reason on an
            // Err. So an unauthorized forward fails loudly here (a clear one-line reason, non-zero exit),
            // never a hopeful banner followed by a silent reset.
            let (dial, service) = (connector.dial(), Service::clone(connector.service()));
            // Matched rather than `?`d: a refusal here is a failed reach like any other, and it has
            // to reach the tail below to be told what the peer would need to serve.
            match connector.preflight(node, port).await {
                Ok(forward) => {
                    println!("forwarding 127.0.0.1:{port} to {dial} ({service})");
                    forward.run().await
                }
                Err(refused) => Err(refused),
            }
        }
        To::Stdout => connector.pipe_stdio(node).await,
        // A sink this build does not have yet: nothing was dialed, so nothing about the peer's
        // service set is relevant. Returned here rather than folded into the tail below.
        To::UnixListener(path) => eyre::bail!(
            "--to unix:{} is reserved, not yet built (bind a port and connect to it, or use `--to -`)",
            path.display()
        ),
    };
    // A dial of a name a bare `swoosh serve` does not bind names the `serve` line that would bind it.
    // This is the seam `swoosh ssh` reaches it through: the launcher `exec`s the system ssh, which
    // re-invokes this bridge as its `ProxyCommand`, so the bridge's stderr is the only place that
    // failure can be explained to the person at the terminal.
    //
    // Attached to EVERY failed reach of that name, refusal or timeout alike, and derived from the
    // name we requested rather than from anything the peer said. A client that said more about one
    // refusal than another would be an oracle the day the wire refusal stops being uniform.
    reached.map_err(|error| Unbound::name_the_entry(error, &requested))
}

/// Stream a peer's exposed service over stdin/stdout (the ssh `ProxyCommand` bridge). Hidden: reached only
/// through `swoosh ssh`, never typed by a user.
#[derive(Debug, Args)]
pub struct TunnelConnectCmd {
    /// the peer to reach, a raw node id already resolved by `swoosh ssh`
    // A raw `NodeId`, not the unified `Peer`, by design: this is an internal ABI, and `swoosh ssh` resolves
    // any petname in-process (against the same home store) BEFORE re-invoking this bridge, so the
    // re-invocation always carries a resolved key. Petname resolution happens once, at the launcher.
    #[arg(value_name = "peer")]
    pub node: NodeId,
    /// the exposed service name to reach on the host
    // REQUIRED, with no default. It defaulted to `default`, a name nothing serves (tightbeam dropped the
    // default service name, and a bare `swoosh serve` binds TWO services, so the single-service leniency
    // cannot cover for it). This is an ABI no user types and `swoosh ssh` always writes the flag, so the
    // name stays a flag here and only the phantom default goes: an omission is now a parse error at the
    // bridge, not a refusal the far gate cannot explain. The public `reach` takes it positionally instead.
    #[arg(long, value_name = "service")]
    pub service: Service,
    /// present a membership badge or capability link to a gated host (a `sheer:` link, parsed
    /// at the boundary)
    #[arg(long, value_name = "link")]
    pub present: Option<Link>,
    /// where to put the stream: the `swoosh ssh` ProxyCommand ABI always passes `-` (stdout). Accepted as
    /// the shared `--to` selector so the bridge speaks the same flag as `reach`; hidden, never typed.
    #[arg(long, value_name = "port | - | unix:PATH", hide = true)]
    pub to: To,
    #[command(flatten)]
    pub reach: transport::ReachArgs,
}

impl swoosh::reaching::Reaching for TunnelConnectCmd {
    fn reach_args(&self) -> &swoosh::transport::ReachArgs {
        &self.reach
    }

    /// `tunnel-connect`'s peer is a raw key (`swoosh ssh` resolved any petname before re-invoking), never a
    /// self-addressing link, so a `--present` slip can never conflict with the peer. Vacuously satisfied.
    fn reject_redundant_present(&self) -> eyre::Result<()> {
        Ok(())
    }

    /// `tunnel-connect` MUST dial under swoosh's OWN persisted key so the family gate proves the identity
    /// the membership badge was minted for, so it declares `Persisted` EXPLICITLY rather than inheriting
    /// the credential's derived `PersistedIfPresent`. A written declaration the compiler requires.
    fn identity(&self) -> swoosh::identity::Identity {
        swoosh::identity::Identity::Persisted
    }

    /// Dialing, and what it dials as. It reaches a peer and never accepts connections under the home key,
    /// so its bind must not write the key's address record (0.9.0 F1); it binds `Persisted` to dial under
    /// swoosh's own key, which is not a reachability claim.
    ///
    /// The bridge reaches a family-gated host, so it presents the member badge rooted at the dialing key.
    /// A `--present` slip is threaded INTO the credential so the ONE resolver owns both slots (slot 1
    /// present-or-badge, slot 2 the fleet badge for a signet-bound slip).
    fn bind_role(&self) -> swoosh::reaching::BindRole {
        swoosh::reaching::BindRole::Dialing(swoosh::credential::Credential::Family {
            present: self.present.clone(),
        })
    }

    /// Uniform dispatch: unpack the reach context and run. `tunnel-connect` reads only the resolved
    /// `present` badge; its peer is a raw key (`swoosh ssh` resolved any petname before invoking this
    /// bridge), so the `connect` runner's contact resolution is a no-op for it.
    async fn run<T: Transport, D: Discovery>(
        self,
        node: &Node<T, D>,
        ctx: swoosh::reaching::ReachCtx<'_>,
    ) -> eyre::Result<()>
    where
        <T::Session as bifrost::Session>::Write: Send + 'static,
        <T::Session as bifrost::Session>::Read: Send + 'static,
    {
        self.run_tunnel_connect(node, ctx.contacts, ctx.present, ctx.membership)
            .await
    }
}

impl TunnelConnectCmd {
    /// Stream the peer's service against this process's stdin/stdout, dialing under swoosh's own identity.
    /// Always `--to -` in practice: this leaf exists only as the ssh `ProxyCommand` bridge.
    ///
    /// The badge presented to a family-gated host is an explicit `--present` link if given, else the
    /// self-signed badge the caller minted from this identity (the signet holder is entitled to sign its
    /// own, fresh per dial). A node gated Open ignores whatever is presented, so presenting is always safe.
    /// Both slots are resolved by the composition root's ONE resolver, so `--present` is not threaded here.
    async fn run_tunnel_connect<T: Transport, D: Discovery>(
        self,
        node: &Node<T, D>,
        contacts: &Contacts,
        present: Option<Link>,
        membership: Option<Link>,
    ) -> eyre::Result<()> {
        // The bridge's peer is a raw key (`swoosh ssh` resolved any petname before re-invoking), so it wraps
        // as `Peer::Raw` and rides the same `connector` path as every other single-target verb.
        connect(
            node,
            contacts,
            &Peer::Raw(self.node),
            self.service,
            present,
            membership,
            self.to,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use bifrost::{NoDiscovery, Node};
    use bifrost_mem::MemTransport;
    use swoosh::contacts::Contacts;

    use super::{Peer, To, connect};

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

    /// The bridge behind `swoosh ssh` names the `serve` line a peer would need when the dial of a
    /// DEFAULTED name fails, and it names it for a failure that never reached a gate at all: this peer
    /// was never bound, so nothing came back to read. That is the property: the line is owed to the
    /// name we SENT, not to any answer, so a client that only said it on a refusal would be reporting
    /// something the uniform refusal is there to withhold.
    #[tokio::test]
    async fn a_failed_dial_of_a_defaulted_name_says_what_the_peer_would_have_to_serve() {
        let node = Node::new(MemTransport::bind(), NoDiscovery);
        // A key nothing is bound at: the dial fails before any peer can answer.
        let absent = Peer::Raw(bifrost::NodeId::from_ed25519_secret(&[3u8; 32]));
        let contacts = Contacts::default();

        let refused = connect(
            &node,
            &contacts,
            &absent,
            "ssh".parse().expect("a service name"),
            None,
            None,
            To::Stdout,
        )
        .await
        .expect_err("a dial to an unbound key fails");
        assert!(
            format!("{refused:#}").contains("swoosh serve ssh=sshd:"),
            "the failure names the line that would bind `ssh`: {refused:#}"
        );

        // A name no verb defaults to is the user's own: they named it, so there is nothing for the
        // client to teach, and nothing is added.
        let plain = connect(
            &node,
            &contacts,
            &absent,
            "web".parse().expect("a service name"),
            None,
            None,
            To::Stdout,
        )
        .await
        .expect_err("a dial to an unbound key fails");
        assert!(
            !format!("{plain:#}").contains("swoosh serve"),
            "a name the user chose gets no serve line appended: {plain:#}"
        );
    }
}
