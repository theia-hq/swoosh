//! `swoosh tunnel connect <peer> --to <port>`: bind a peer's exposed service to a local port.
//!
//! Drives tightbeam's tunnel [`Connector`] directly under swoosh's OWN identity: the public port-forward
//! form (`ssh -L` shaped), where a local TCP port carries each connection to the peer's exposed service
//! over the overlay. Distinct from the hidden `tunnel-connect` leaf (the `swoosh ssh` ProxyCommand ABI,
//! which is `--stdio`-only and never typed): this is the port-bound form a user reaches directly. Both
//! surfaces share the one [`connect`](crate::commands::tunnel_connect::connect) runner, selected here by
//! [`Mode::Port`].

use bifrost::{Discovery, Node, Transport};
use clap::Args;

use crate::commands::tunnel_connect::{self, Dial, Mode};
use crate::transport::ReachArgs;

/// Reach a peer's exposed service and bind it to a local port.
#[derive(Debug, Args)]
pub struct TunnelConnectCmd {
    /// who to reach: a raw node id, or a `sheer:` capability link
    // Field is `node`, not `peer`: the clap arg id derives from the field name, so a `peer` field would
    // collide with the `--peer` dial hint in the flattened `ReachArgs`. `value_name` keeps usage as `<peer>`.
    #[arg(value_name = "peer")]
    pub node: Dial,
    /// local port to forward to the peer
    #[arg(long, value_name = "port")]
    pub to: u16,
    /// which exposed service to reach
    #[arg(long, value_name = "service", default_value = "default")]
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
        tunnel_connect::connect(
            node,
            self.node,
            self.service,
            self.present,
            Mode::Port(self.to),
        )
        .await
    }
}
