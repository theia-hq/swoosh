//! `swoosh serve`: be online. Print this node's address, then answer reach diagnostics (`ping`/`speed`)
//! from peers your signet admits. This is the peer a `swoosh ping` / `swoosh speed` client dials.
//!
//! Sugar for `swoosh tunnel expose diag=diag:`: it drives the SAME gated exposer, so `serve` answers
//! diagnostics behind the family gate by default rather than to anyone. `--public` is the one deliberate
//! opt-out to the old "anyone can ping me" behaviour. There is no bespoke accept loop: a diagnostic
//! client reaches `diag:` only through the tunnel's `Request{service}` handshake, and the gate is not
//! optional, so `serve` cannot answer an ungated peer.

use bifrost::{Discovery, Node, NodeId, Session, Transport};
use clap::Args;
use nauthy::Denylist;
use tightbeam::tunnel::{self, Exposer, Services};

use crate::commands::tunnel::expose::registry;
use crate::transport::ReachArgs;

/// The service `serve` exposes: swoosh's own gated `diag:` handler, under the `diag` name a client
/// requests. Sugar for the `diag=diag:` entry a user would otherwise type into `tunnel expose`.
const DIAG_SERVICE: &str = "diag=diag:";

/// Answer reach diagnostics from peers your signet admits, until interrupted.
#[derive(Debug, Args)]
pub struct ServeCmd {
    /// Answer ANYONE, unauthenticated: the one deliberate opt-out from the signet gate. `diag:` carries
    /// no auth of its own, so this is the old "anyone can ping me" behaviour, made explicit.
    #[arg(long)]
    pub public: bool,
    #[command(flatten)]
    pub reach: ReachArgs,
}

impl ServeCmd {
    /// Announce this node's address, then run the gated `diag:` exposer until Ctrl-C. Builds the SAME
    /// registry and gate `tunnel expose` does (through the shared `registry`/`resolve_gate` seams), so
    /// `serve` is exactly `tunnel expose diag=diag:` with a friendlier banner; `--public` opens the gate.
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
        let services = Services::parse(&[DIAG_SERVICE.to_owned()])?;
        // Resolve the gate before announcing readiness: an unprovisioned node with no `--public` fails
        // HERE, through the ONE shared policy point, rather than ever serving on a permissive default.
        let gate = tunnel::resolve_gate(self.public, signet, denylist)?;
        let exposer = Exposer::new(services, registry(host_seed)?, gate)?;

        let addr = node.local_addr();
        println!("swoosh ready. peers can reach this node at:\n");
        println!("    {}\n", addr.node);
        // Direct-only transports (quirk) cannot discover this address, so print the dialable hint a
        // client feeds back via `--peer`. Self-discovering transports (iroh) carry no local hints here,
        // so this loop prints nothing for them.
        for hint in &addr.hints {
            println!("    --peer {}={hint}\n", addr.node);
        }
        println!(
            "answering ping and speed (gate: {}). press ctrl-c to stop.",
            self.gate_description(signet)
        );

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

    /// A one-line description of the effective gate, for the readiness banner: trust made visible, matching
    /// what `tunnel expose` prints.
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
