//! `swoosh tunnel expose <name=addr>...`: publish local services under swoosh's key, gated by the signet.
//!
//! Wraps tightbeam's [`ExposeCmd`] in-process under swoosh's OWN persisted identity: the node binds the
//! same key `serve` and `swoosh ssh` bind, reads the trusted signet with
//! [`load_signet`](tightbeam::config::load_signet), and derives the ssh host seed from swoosh's secret,
//! so an `ssh=sshd:` service presents the host key a client pins and a `swoosh grant share` link roots at the
//! key peers dial. `--public` and `--quiet` live on THIS verb (not root), and reach comes via the shared
//! [`ReachArgs`](crate::transport::ReachArgs), flattened like every other reaching verb: no tightbeam
//! `--offline`/`--bind-addr` here, so the surface stays swoosh's.

use bifrost::{Discovery, Node, NodeId, Session, Transport};
use clap::Args;
use tightbeam::{Brand, ExposeCmd};

use crate::transport::ReachArgs;

/// How the readiness banner names this tool, so `swoosh tunnel expose` says "swoosh tunnel ready" and
/// points at `swoosh grant share` for minting a link, never at `tightbeam`.
const BRAND: Brand = Brand {
    ready: "swoosh tunnel",
    share: "swoosh grant share",
};

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
    /// Serve the exposed services under swoosh's identity: read the signet the default gate trusts, then
    /// hand off to tightbeam's exposer with swoosh's own ssh host seed (computed in the root before the
    /// secret was consumed by the transport bind). `--public` overrides the signet gate; a `sshd:` service
    /// stays gated regardless.
    pub async fn run<T: Transport, D: Discovery>(
        self,
        node: &Node<T, D>,
        host_seed: [u8; 32],
        signet: Option<NodeId>,
    ) -> eyre::Result<()>
    where
        <T::Session as Session>::Write: Send + 'static,
        <T::Session as Session>::Read: Send + 'static,
    {
        ExposeCmd {
            services: self.services,
            public: self.public,
            quiet: self.quiet,
        }
        .run(node, host_seed, signet, BRAND)
        .await
    }
}
