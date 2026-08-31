//! `swoosh tunnel expose <name=addr>...`: publish local services under swoosh's key, gated by the signet.
//!
//! Drives tightbeam's tunnel LIBRARY directly under swoosh's OWN persisted identity: the node binds the
//! same key `serve` and `swoosh ssh` bind, gates on the signet read from swoosh's own store, and derives
//! the ssh host seed from swoosh's secret, so an `ssh=sshd:` service presents the host key a client pins
//! and a `swoosh grant issue` link roots at the key peers dial. swoosh assembles the handler registry
//! itself (tightbeam's shipped `fetch`/`sshd` plus swoosh's own `diag:`), builds the gate through the
//! shared [`resolve_gate`](tightbeam::tunnel::resolve_gate) policy, and prints its OWN readiness banner.
//! `--public` and `--quiet` live on THIS verb (not root), and reach comes via the shared
//! [`ReachArgs`](crate::transport::ReachArgs), flattened like every other reaching verb: no tightbeam
//! `--offline`/`--bind-addr` here, so the surface stays swoosh's.

use std::sync::Arc;

use bifrost::{Discovery, Node, NodeId, Session, Transport};
use clap::Args;
use futures::FutureExt as _;
use nauthy::Denylist;
use tightbeam::tunnel::{self, Exposer, Handler, Registry, ServeFn, Services};

use crate::transport::ReachArgs;

/// Expose a local service to peers who hold this node's key, gated by your signet.
#[derive(Debug, Args)]
pub struct TunnelExposeCmd {
    /// expose local services as `name=addr` (bare `addr` = `default`)
    #[arg(required = true, value_name = "name=addr")]
    pub services: Vec<String>,
    /// Expose to ANYONE, unauthenticated: the one deliberate opt-out from the signet. Refused for a shell
    /// service (`sshd:`), which has no auth of its own.
    #[arg(long)]
    pub public: bool,
    /// Suppress the readiness banner (the node id, services, and gate), for unattended/CI use.
    #[arg(long)]
    pub quiet: bool,
    #[command(flatten)]
    pub reach: ReachArgs,
}

impl TunnelExposeCmd {
    /// Serve the exposed services under swoosh's identity by driving the tunnel core directly: parse the
    /// services, resolve the gate from swoosh's own signet + denylist (through the shared `resolve_gate`
    /// policy, so `--public` opens, else a family gate on the signet, else a loud error), assemble the
    /// handler registry (tightbeam's shipped `fetch`/`sshd` plus swoosh's `diag:`), print swoosh's banner,
    /// and run the exposer. `--public` overrides the signet gate; a `sshd:` service stays gated regardless.
    pub async fn run<T: Transport, D: Discovery>(
        self,
        node: &Node<T, D>,
        host_seed: [u8; 32],
        signet: Option<NodeId>,
        denylist: Denylist,
    ) -> eyre::Result<()>
    where
        <T::Session as Session>::Write: Send + 'static,
        <T::Session as Session>::Read: Send + 'static,
    {
        let services = Services::parse(&self.services)?;
        // Build the gate before announcing readiness: an unprovisioned node with no `--public` fails HERE,
        // loudly, through the ONE shared policy point, rather than ever serving on a permissive default.
        let gate = tunnel::resolve_gate(self.public, signet, denylist)?;
        // The core assembles the exposer, enforcing the sshd-cannot-be-public (and now diag-cannot-be-
        // public) invariant before any banner is printed, so a refused pairing never advertises a service
        // it will not serve.
        let exposer = Exposer::new(services.clone(), registry(host_seed)?, gate)?;
        if !self.quiet {
            expose_banner(node.node_id(), services.names(), &self.gate_description(signet));
        }
        exposer.run(node).await
    }

    /// A one-line description of the effective gate, for the readiness banner: trust made visible.
    fn gate_description(&self, signet: Option<NodeId>) -> String {
        if self.public {
            "public (anyone, unauthenticated)".to_owned()
        } else {
            match signet {
                Some(root) => format!("signet {}", root.short()),
                None => "unprovisioned".to_owned(),
            }
        }
    }
}

/// Print swoosh's readiness banner: the copyable node id set off by blank lines, a header stating swoosh
/// tunnel is ready, and a trailer naming the exposed services, the effective gate, and how to stop. Points
/// at `swoosh grant issue` (swoosh's own mint verb), never at tightbeam. Only public material is printed
/// (the node id); the host seed and the signet secret never appear. Withheld under `--quiet`.
fn expose_banner<'a>(node_id: NodeId, names: impl Iterator<Item = &'a str>, gate: &str) {
    println!("swoosh tunnel ready. peers can reach these services at:\n");
    println!("    {node_id}                     (share this key, or mint a link with `swoosh grant issue`)\n");
    let names: Vec<&str> = names.collect();
    println!("exposing {}. gate: {}. ctrl-c to stop.", names.join(", "), gate);
}

/// Assemble the handler registry swoosh serves: tightbeam's shipped raw-forward handlers (`fetch`, and
/// `sshd` under the `ssh` feature) plus swoosh's own gated `diag:`. `extend` is add-only, so `diag:` (a new
/// scheme) is accepted while a reserved built-in (`fetch`/`sshd`) could never be shadowed.
///
/// The ONE assembly the product verb and the `gated_diag` proof test both build, so the test exercises the
/// identical registry swoosh serves rather than a hand-rolled near-copy.
pub fn registry(host_seed: [u8; 32]) -> eyre::Result<Registry> {
    let registry = Registry::new().with("fetch", tightbeam::handlers::fetch());
    #[cfg(feature = "ssh")]
    let registry = registry.with("sshd", tightbeam::handlers::sshd(host_seed));
    #[cfg(not(feature = "ssh"))]
    let _ = host_seed;
    registry.extend(Registry::new().with("diag", diag_handler()))
}

/// The `diag:` handler swoosh injects into the exposer: reach diagnostics (ping/speed) behind the node's
/// gate. It answers one diagnostic request over the admitted stream. GATED: `SpeedSource{None}` is an
/// unbounded anonymous egress drain, so an open gate over it (`--public diag:`) is refused at
/// [`Exposer::new`]; the family gate is the terminator until the responder-side bound lands.
fn diag_handler() -> Handler {
    let serve: ServeFn = Arc::new(|_admitted, mut writer, mut reader| {
        async move {
            diag::answer(&mut writer, &mut reader).await?;
            Ok(())
        }
        .boxed()
    });
    Handler::gated(serve)
}
