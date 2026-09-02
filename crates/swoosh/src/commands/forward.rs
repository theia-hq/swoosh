//! `swoosh forward <peer> --to <port | - | unix:PATH>`: bind a peer's served service to a local port,
//! stream it to stdout, or (reserved) a local unix listener.
//!
//! Drives tightbeam's tunnel [`Connector`] directly under swoosh's OWN identity: the public forward form
//! (`ssh -L` shaped), where a local port carries each connection to the peer's served service over the
//! overlay, or `--to -` streams the single service to stdout (compose with the shell). Distinct from the
//! hidden `tunnel-connect` leaf (the `swoosh ssh` ProxyCommand ABI, which is `--to -`-only and never
//! typed): this is the form a user reaches directly. Both surfaces share the one
//! [`connect`](crate::commands::tunnel_connect::connect) runner, selected here by the single [`To`].

use bifrost::{Discovery, Node, Transport};
use clap::Args;

use crate::commands::tunnel_connect::{self, Dial, To};
use crate::transport::ReachArgs;

/// Bind a peer's served service to a local port, stream it to stdout, or a reserved unix listener.
#[derive(Debug, Args)]
pub struct ForwardCmd {
    /// who to reach: a raw node id, or a `sheer:` capability link
    // Field is `node`, not `peer`: the clap arg id derives from the field name, so a `peer` field would
    // collide with the `--peer` dial hint in the flattened `ReachArgs`. `value_name` keeps usage as `<peer>`.
    #[arg(value_name = "peer")]
    pub node: Dial,
    /// where to put the stream: a local port, `-` for stdout, or `unix:<path>`
    #[arg(long, value_name = "port | - | unix:PATH")]
    pub to: To,
    /// which served service to reach
    #[arg(long, value_name = "service", default_value = "default")]
    pub service: String,
    /// present a `sheer:` capability link alongside a raw node id
    #[arg(long, value_name = "link")]
    pub present: Option<String>,
    #[command(flatten)]
    pub reach: ReachArgs,
}

impl crate::reaching::Reaching for ForwardCmd {
    fn reach_args(&self) -> &crate::transport::ReachArgs {
        &self.reach
    }

    /// `forward` is a dial-only client: it presents its OWN `--present` link (never swoosh's identity),
    /// so it dials as a stranger by construction. `Anonymous` is a NAMED no-badge, not a forgotten one,
    /// and derives `Ephemeral`.
    fn credential(&self) -> crate::credential::Credential {
        crate::credential::Credential::Anonymous
    }
}

impl ForwardCmd {
    /// Drive the sink `--to` names: bind a local port and forward each connection, stream to stdout, or the
    /// reserved unix listener, all over the overlay under swoosh's identity.
    pub async fn run<T: Transport, D: Discovery>(self, node: &Node<T, D>) -> eyre::Result<()> {
        tunnel_connect::connect(node, self.node, self.service, self.present, self.to).await
    }
}
