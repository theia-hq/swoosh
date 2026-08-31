//! `swoosh serve [<name>=<svc>...]`: be a node. Publish named services behind this node's signet gate,
//! then stay reachable so peers who hold this node's key can reach them.
//!
//! This IS the node. `swoosh serve` with no services answers reach diagnostics (`ping`/`speed`) from
//! peers your signet admits: `diag` is the default service. `swoosh serve ssh=sshd: diag=diag:` publishes
//! more. It drives tightbeam's tunnel LIBRARY (`Exposer`) directly under swoosh's OWN persisted identity:
//! the node binds the same key `swoosh ssh` and a minted `swoosh grant issue` link root at, gates on the
//! signet read from swoosh's own store, and derives the ssh host seed from swoosh's secret, so an
//! `ssh=sshd:` service presents the host key a client pins. swoosh assembles the whole handler registry
//! itself (`fetch:`, `diag:`, and `sshd:` under the `ssh` feature), builds the gate through the shared
//! [`resolve_gate`](tightbeam::tunnel::resolve_gate) policy, and prints its OWN readiness banner. `--public`
//! and `--quiet` live on THIS verb (not root), and reach comes via the shared
//! [`ReachArgs`](crate::transport::ReachArgs), flattened like every other reaching verb.

use std::sync::Arc;

use bifrost::{Discovery, Node, NodeId, Session, Transport};
use clap::Args;
use futures::FutureExt as _;
use nauthy::Denylist;
use tightbeam::tunnel::{self, Exposer, Handler, Registry, ServeFn, Services};

use crate::transport::ReachArgs;

/// The default service `serve` publishes when none is named: swoosh's own gated `diag:` handler, under the
/// `diag` name a client requests. A bare `swoosh serve` answers reach diagnostics behind the signet gate.
const DEFAULT_SERVICE: &str = "diag=diag:";

/// Be a node: publish these services behind your signet gate, then stay reachable.
#[derive(Debug, Args)]
pub struct ServeCmd {
    /// publish local services as `name=svc` (bare `swoosh serve` = `diag=diag:`, reach diagnostics)
    #[arg(value_name = "name=svc")]
    pub services: Vec<String>,
    /// Serve to ANYONE, unauthenticated: the one deliberate opt-out from the signet gate. Refused for a
    /// keyless shell (`sshd:`) or an unbounded drain (`diag:`), which have no auth of their own.
    #[arg(long)]
    pub public: bool,
    /// Suppress the readiness banner (the node id, services, and gate), for unattended/CI use.
    #[arg(long)]
    pub quiet: bool,
    #[command(flatten)]
    pub reach: ReachArgs,
}

impl ServeCmd {
    /// Serve the named services (default `diag=diag:`) under swoosh's identity by driving the tunnel core
    /// directly: parse the services, resolve the gate from swoosh's own signet + denylist (through the
    /// shared `resolve_gate` policy, so `--public` opens, else a family gate on the signet), assemble the
    /// handler registry (`fetch:`, `diag:`, and `sshd:` under the `ssh` feature), print swoosh's banner, and
    /// run the exposer. A `sshd:`/`diag:` service stays gated regardless. The `signet` here is already
    /// resolved by the composition root: a provisioned signet if one was adopted, else this node's OWN key
    /// (person-zero self-trusts), so a plain node gates on itself rather than failing "no signet".
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
        let requested = if self.services.is_empty() {
            vec![DEFAULT_SERVICE.to_owned()]
        } else {
            self.services.clone()
        };
        let services = Services::parse(&requested)?;
        // Resolve the gate before announcing readiness: an unprovisioned node with no `--public` fails
        // HERE, through the ONE shared policy point, rather than ever serving on a permissive default.
        let gate = tunnel::resolve_gate(self.public, signet, denylist)?;
        // The core assembles the exposer, enforcing the sshd-cannot-be-public (and diag-cannot-be-public)
        // invariant before any banner is printed, so a refused pairing never advertises a service it will
        // not serve.
        let exposer = Exposer::new(services.clone(), registry(host_seed)?, gate)?;

        if !self.quiet {
            let addr = node.local_addr();
            println!("swoosh ready. peers can reach this node at:\n");
            println!("    {}\n", addr.node);
            // Direct-only transports (quirk) cannot discover this address, so print the dialable hint a
            // client feeds back via `--peer`. Self-discovering transports (iroh) carry no local hints here,
            // so this loop prints nothing for them.
            for hint in &addr.hints {
                println!("    --peer {}={hint}\n", addr.node);
            }
            let names: Vec<&str> = services.names().collect();
            println!(
                "serving {} (gate: {}). ctrl-c to stop.",
                names.join(", "),
                self.gate_description(signet, addr.node)
            );
        }

        // The exposer runs until cancelled; a Ctrl-C ends it gracefully by cancelling the run.
        tokio::select! {
            result = exposer.run(node) => result,
            signalled = tokio::signal::ctrl_c() => {
                signalled?;
                println!("\nshutting down.");
                node.close().await;
                Ok(())
            }
        }
    }

    /// A one-line description of the effective gate, for the readiness banner: trust made visible. `self_id`
    /// is this node's own id, so the banner can say "self" when the gate roots at the node's OWN key (a
    /// person-zero node with no provisioned signet self-trusts) rather than naming its own id as a "signet".
    fn gate_description(&self, signet: Option<NodeId>, self_id: NodeId) -> String {
        if self.public {
            "public (anyone, unauthenticated)".to_owned()
        } else {
            match signet {
                Some(root) if root == self_id => {
                    "self (person-zero: this node and its devices)".to_owned()
                }
                Some(root) => format!("signet {}", root.short()),
                None => "unprovisioned".to_owned(),
            }
        }
    }
}

/// Assemble the whole handler registry swoosh serves: the HTTP egress `fetch:`, the gated diagnostic
/// `diag:`, and (under the `ssh` feature) the keyless shell `sshd:`. swoosh is the one crate that depends on
/// every service crate, so it is the one place these are wired: tightbeam names no service crate and ships
/// no built-in, and this function injects them all with `.with(...)`. `extend` stays available for add-only
/// merges, but swoosh builds one registry directly here.
///
/// The ONE assembly the product verb and the `gated_diag` proof test both build, so the test exercises the
/// identical registry swoosh serves rather than a hand-rolled near-copy.
pub fn registry(host_seed: [u8; 32]) -> eyre::Result<Registry> {
    let registry = Registry::new()
        .with("fetch", fetch_handler())
        .with("diag", diag_handler());
    #[cfg(feature = "ssh")]
    let registry = registry.with("sshd", sshd_handler(host_seed));
    #[cfg(not(feature = "ssh"))]
    let _ = host_seed;
    Ok(registry)
}

/// The `fetch:` handler swoosh injects: the node acts as an HTTP client and streams an origin response back
/// over the admitted stream. It carries its own SSRF guard, so it does not require the gate (a `--public
/// fetch:` is a deliberate choice, not an accidental keyless shell).
fn fetch_handler() -> Handler {
    let serve: ServeFn = Arc::new(|_admitted, mut writer, mut reader| {
        async move {
            fetch::serve_fetch(&mut writer, &mut reader).await?;
            Ok(())
        }
        .boxed()
    });
    Handler::open(serve)
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

/// The `sshd:` handler swoosh injects under the `ssh` feature: a keyless shell. GATED, because a shell has
/// no auth of its own so the gate IS its authentication; an open gate over it is refused at
/// [`Exposer::new`]. Captures the ssh host-key seed the caller derived from swoosh's identity.
#[cfg(feature = "ssh")]
fn sshd_handler(host_seed: [u8; 32]) -> Handler {
    let serve: ServeFn = Arc::new(move |admitted, writer, reader| {
        async move {
            sshh::serve(admitted, host_seed, writer, reader).await?;
            Ok(())
        }
        .boxed()
    });
    Handler::gated(serve)
}
