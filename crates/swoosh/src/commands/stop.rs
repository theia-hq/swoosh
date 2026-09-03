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
use tokio::io::AsyncReadExt as _;

use crate::commands::serve::{CONTROL_STOP_SERVICE, STOP_ACK};
use crate::contacts::Contacts;
use crate::peer::Peer;
use crate::transport::ReachArgs;

/// Stop a peer's node (stop it serving), addressed by its public key or a `sheer:` capability link.
#[derive(Debug, Args)]
pub struct StopCmd {
    /// the peer to reach: a petname (`alice`, `alice/desk`), a raw node id, or a `sheer:` link
    #[arg(value_name = "peer")]
    pub peer: Peer,
    /// present a `sheer:` cap link to a cap-gated peer (a delegate's slip)
    #[arg(
        long,
        value_name = "link",
        long_help = "Optional: your own devices need no link, the dial presents the self-signed \
                     membership badge under this identity. Pass a `sheer:` slip only to reach as a delegate."
    )]
    pub present: Option<crate::credential::SheerLink>,
    #[command(flatten)]
    pub reach: ReachArgs,
}

impl crate::reaching::Reaching for StopCmd {
    fn reach_args(&self) -> &crate::transport::ReachArgs {
        &self.reach
    }

    /// `stop` reaches the peer's family-gated `control.stop` service, so it presents the member badge
    /// rooted at the dialing key (only a family member may stop the node). `Family` fuses the identity to
    /// `PersistedIfPresent`. The effective slip is the FOLD of a self-addressing `sheer:` link-as-peer with
    /// an explicit `--present`, threaded INTO the credential so the ONE resolver owns both slots.
    fn credential(&self) -> crate::credential::Credential {
        crate::credential::Credential::Family {
            present: self.peer.self_present().or_else(|| self.present.clone()),
        }
    }

    fn reject_redundant_present(&self) -> eyre::Result<()> {
        self.peer.reject_redundant_present(self.present.as_ref())
    }

    fn identity(&self) -> crate::identity::Identity {
        self.credential().identity()
    }

    /// Uniform dispatch: unpack the reach context and run. `stop` reads the resolved `present` badge and
    /// `contacts` (to resolve a petname like `me/qat` in its peer slot); it ignores `transport` and `key`.
    async fn run<T: Transport, D: Discovery>(
        self,
        node: &Node<T, D>,
        ctx: crate::reaching::ReachCtx<'_>,
    ) -> eyre::Result<()>
    where
        <T::Session as bifrost::Session>::Write: Send + 'static,
        <T::Session as bifrost::Session>::Read: Send + 'static,
    {
        self.run_stop(node, ctx.contacts, ctx.present, ctx.membership)
            .await
    }
}

impl StopCmd {
    /// Reach the peer's gated `control.stop` service and trigger a graceful stop. Presents the resolved
    /// `present` (the self-signed membership badge, or an explicit `--present` link) so the node's family
    /// gate admits the stream; a node that does not admit this caller refuses LOUDLY here, never a silent
    /// no-op.
    async fn run_stop<T: Transport, D: Discovery>(
        self,
        node: &Node<T, D>,
        contacts: &Contacts,
        present: Option<String>,
        membership: Option<String>,
    ) -> eyre::Result<()> {
        // Slots 1 and 2 are ALREADY resolved by the composition root's ONE resolver (present-or-badge in
        // slot 1, a fleet badge in slot 2 only for a signet-bound slip); the fold in `credential()` routed a
        // link-as-peer through that same resolver, and the redundant-present conflict was rejected there too
        // (`Reaching::reject_redundant_present`), so the verb never threads `--present` itself.
        let connector = self.peer.connector(
            contacts,
            CONTROL_STOP_SERVICE.to_owned(),
            present,
            membership,
        )?;
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
