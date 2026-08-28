//! `swoosh tunnel-connect`: the hidden in-process ProxyCommand behind `swoosh ssh`.
//!
//! Not a user verb. It is the executable `swoosh ssh` names in ssh's `ProxyCommand`, invoked on THIS
//! binary via `current_exe()` (not a separate `tightbeam` binary on PATH). It binds a node under swoosh's
//! OWN identity and pipes a peer's exposed service over stdin/stdout, so ssh speaks its protocol to a far
//! sshd across the overlay. Wrapping tightbeam's [`ConnectCmd`] as a library keeps one identity throughout
//! and drops the PATH/binary dependency, and — because the dial carries swoosh's key — a membership badge
//! presented here (step 6) binds to the identity the family gate will actually prove.
//!
//! The public port-forward form (`tunnel connect --to <port>`) is a separate, later surface; this leaf
//! carries only the `--stdio` plumbing, so it stays hidden from help and `tree`.

use bifrost::{Discovery, Node, NodeId, Transport};
use clap::Args;
use tightbeam::connect::{ConnectCmd, Target};

use crate::transport;

/// Pipe a peer's exposed service over stdin/stdout (the ssh `ProxyCommand` bridge). Hidden: reached only
/// through `swoosh ssh`, never typed by a user.
#[derive(Debug, Args)]
pub struct TunnelConnectCmd {
    /// the peer to reach, a raw node id already resolved by `swoosh ssh`
    #[arg(value_name = "peer")]
    pub node: NodeId,
    /// the exposed service name to reach on the host
    #[arg(long, default_value = "default")]
    pub service: String,
    /// present a membership badge or capability link to a family/cap-gated host
    #[arg(long, value_name = "link")]
    pub present: Option<String>,
    #[command(flatten)]
    pub reach: transport::ReachArgs,
}

impl TunnelConnectCmd {
    /// Pipe the peer's service against this process's stdin/stdout, dialing under swoosh's own identity.
    /// Always `--stdio`: this leaf exists only as the ssh `ProxyCommand` bridge.
    pub async fn run<T: Transport, D: Discovery>(self, node: &Node<T, D>) -> eyre::Result<()> {
        ConnectCmd {
            target: Target::Node(self.node),
            to: None,
            stdio: true,
            service: self.service,
            present: self.present,
        }
        .run(node)
        .await
    }
}
