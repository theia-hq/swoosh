//! `swoosh stop <peer>`: stop a peer's node (stop it serving), addressed by its public key or a `sheer:`
//! capability link.
//!
//! The remote half of node lifecycle: you dial a node's gated `control.stop` service and, once admitted,
//! trigger a graceful teardown, the same stop a Ctrl-C or a `serve --for` deadline gives locally. It stops
//! the DAEMON (the node stops serving), it does NOT power off the machine.
//!
//! `control.stop` is family-gated like `ping`/`speed`/`beam`, so `stop` presents the same self-signed
//! membership badge (or an explicit `--present` link) to prove membership before the node admits the
//! stream. For a single-owner node this means only your own devices can stop it, which is correct for the
//! qat CI-teardown consumer. Hardening the lifecycle further (an arm->confirm nonce + a single-use
//! device-bound destroy-cap, ideally owner-only) is a flagged follow that needs an Adversary review before
//! `control.stop` is trusted on a multi-delegate node.
//!
//! A refusal is a LOUD typed error, never a silent success: if the node's gate does not admit this caller,
//! opening the control stream fails and `stop` reports the refusal and exits non-zero.

use bifrost::{Discovery, Node, Session as _, Transport};
use clap::Args;
use tightbeam::tunnel::Connector;
use tokio::io::AsyncReadExt as _;

use crate::commands::serve::{CONTROL_STOP_SERVICE, STOP_ACK};
use crate::commands::tunnel_connect::Dial;
use crate::transport::ReachArgs;

/// Stop a peer's node (stop it serving), addressed by its public key or a `sheer:` capability link.
#[derive(Debug, Args)]
pub struct StopCmd {
    /// who to stop: a raw node id, or a `sheer:` capability link
    // Named `target`, not `peer`: the flattened `ReachArgs` already owns a `--peer` arg (its clap id is
    // `peer`), so a positional field named `peer` would collide two args under one clap id. The help still
    // reads `<peer>` via `value_name`.
    #[arg(value_name = "peer")]
    pub target: Dial,
    /// present a `sheer:` capability link alongside a raw node id
    #[arg(long, value_name = "link")]
    pub present: Option<String>,
    #[command(flatten)]
    pub reach: ReachArgs,
}

impl StopCmd {
    /// Reach the peer's gated `control.stop` service and trigger a graceful stop. Presents `self_badge` (the
    /// self-signed membership badge, or an explicit `--present` link) so the node's family gate admits the
    /// stream; a node that does not admit this caller refuses LOUDLY here, never a silent no-op.
    pub async fn run<T: Transport, D: Discovery>(
        self,
        node: &Node<T, D>,
        self_badge: Option<String>,
    ) -> eyre::Result<()> {
        // Present an explicit `--present` link if given, else the self-signed badge minted from this
        // identity: the `control.stop` service is gated, so the stream must prove membership to be admitted.
        let present = self.present.or(self_badge);
        let connector = match &self.target {
            Dial::Node(id) => Connector::to_node(*id, CONTROL_STOP_SERVICE.to_owned(), present),
            Dial::Capability(link) => Connector::from_link(link, CONTROL_STOP_SERVICE.to_owned())?,
        };
        let dial = connector.dial();
        println!("stopping {dial}...");

        // A service-scoped session whose one `open_bi` speaks the `control.stop` request and presents the
        // badge. On admission the node cancels its teardown token and writes one ack byte; a refusal maps to
        // a loud stream error here (the false-success fix: a refusal is a typed loud error, never silent).
        let session = connector.open_service(node).await?;
        let (writer, mut reader) = session
            .open_bi()
            .await
            .map_err(|error| eyre::eyre!("could not stop {dial}: {error}"))?;

        // Read the node's ack byte: proof the stop was actioned, not merely that the dial was admitted. The
        // node closes right after, so an unexpected EOF before the ack is itself the confirmation the node
        // is going down; only a wrong byte on a live stream is a surprise worth naming.
        let mut ack = [0u8; 1];
        match reader.read_exact(&mut ack).await {
            Ok(_) if ack[0] == STOP_ACK => {}
            Ok(_) => eyre::bail!("stopped {dial}, but it sent an unexpected control reply"),
            // The node tore the stream down as it stopped: expected on a successful stop.
            Err(_eof) => {}
        }
        drop(writer);

        println!("stopped {dial}.");
        node.close().await;
        Ok(())
    }
}
