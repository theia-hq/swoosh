//! `swoosh tunnel connect <peer> --to <port>`: bind a peer's exposed service to a local port.
//!
//! Wraps tightbeam's [`ConnectCmd`] in-process under swoosh's OWN identity: the public port-forward form
//! (`ssh -L` shaped), where a local TCP port carries each connection to the peer's exposed service over
//! the overlay. Distinct from the hidden `tunnel-connect` leaf (the `swoosh ssh` ProxyCommand ABI, which
//! is `--stdio`-only and never typed): this is the port-bound form a user reaches directly.

use bifrost::{Discovery, Node, Transport};
use clap::Args;
use tightbeam::ConnectCmd;
use tightbeam::connect::Target;

use crate::transport::ReachArgs;

/// Reach a peer's exposed service and bind it to a local port.
#[derive(Debug, Args)]
pub struct TunnelConnectCmd {
    /// who to reach: a raw node id, or a `sheer:` capability link
    #[arg(value_name = "peer")]
    pub peer: Target,
    /// local port to forward to the peer
    #[arg(long, value_name = "port")]
    pub to: u16,
    /// which exposed service to reach
    #[arg(long, default_value = "default")]
    pub service: String,
    /// present a `sheer:` capability link alongside a raw node id
    #[arg(long, value_name = "link")]
    pub present: Option<String>,
    #[command(flatten)]
    pub reach: ReachArgs,
}

impl TunnelConnectCmd {
    /// Bind the local port and forward each connection to the peer's service over the overlay.
    pub async fn run<T: Transport, D: Discovery>(self, node: &Node<T, D>) -> eyre::Result<()> {
        ConnectCmd {
            target: self.peer,
            to: Some(self.to),
            stdio: false,
            service: self.service,
            present: self.present,
        }
        .run(node)
        .await
    }
}
