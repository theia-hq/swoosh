//! `swoosh stop [--at <peer>]`: stop a node (stop it serving).
//!
//! Follows the one control grammar (delib-47): BARE stops YOUR OWN node over the local control socket,
//! `--at <peer>` stops a peer's. Bare `stop` resolves the resident's socket, asks it to stop, and prints
//! the pid that answered; with no resident it teaches (`swoosh serve --resident`) and exits non-zero. A
//! foreground `serve` without `--resident` is still stopped with Ctrl-C or an `--expires` deadline.
//! `stop --at <peer>` is the remote half: you dial the peer's gated `control.stop`
//! service and, once admitted, trigger a graceful teardown, the same stop a Ctrl-C or a `serve --expires`
//! deadline gives. It stops the NODE (the node stops serving), it does NOT power off the machine.
//!
//! `control.stop` is MEMBER-only, not merely family-gated: the node admits a whole-node membership badge
//! (your own devices), and refuses a delegated slip at the route's member floor with the same uniform
//! refusal a gate miss gives, before any `Response::Ok`. So `stop --at` presents the self-signed membership
//! badge under your identity; a `--present` slip reaches the gate but cannot stop the node. For a fleet
//! this means any of your own devices can stop it, which is correct for the qat CI-teardown consumer.
//! Hardening the lifecycle further (an arm->confirm nonce + a single-use device-bound destroy-cap, ideally
//! owner-only so another fleet device cannot stop the node) is a flagged follow that needs an Adversary
//! review before `control.stop` is trusted across a multi-device fleet.
//!
//! A refusal is a LOUD typed error, never a silent success: if the node's gate does not admit this caller,
//! opening the control stream fails and `stop` reports the refusal and exits non-zero.
//!
//! The one tolerant case is the teardown RACE: the stream open can fail because the node is already tearing
//! itself down in response to the request (the goal state), not because the dial was refused. On a
//! non-refusal stream-open failure the verb probes the peer for a bounded window: a peer that stays
//! unreachable is gone or stopping, so the stop is reported as completed; a peer that still accepts a
//! connection is live, so the original failure stands loudly (never masked).

use core::time::Duration;

use bifrost::{Discovery, Node, NodeId, Session as _, Transport};
use clap::Args;
use nauthy::{Link, Service};
use tokio::io::AsyncReadExt as _;

use crate::commands::serve::{CONTROL_STOP_SERVICE, STOP_ACK};
use crate::contacts::Contacts;
use crate::home::Home;
use crate::node_client::{ControlClient, NodeClient as _, control_error_report};
use crate::peer::Peer;
use crate::transport::ReachArgs;

/// How long a failed control-stream open is probed before it reads as a completed stop. The node closes its
/// endpoint right after a graceful teardown, so an unreachable peer over this window is gone or stopping; a
/// live peer answers a probe connect at once. Bounded so a peer that is merely slow still fails loudly.
const STOP_PROBE_WINDOW: Duration = Duration::from_secs(3);

/// The delay between probe dials inside [`STOP_PROBE_WINDOW`].
const STOP_PROBE_INTERVAL: Duration = Duration::from_millis(100);

/// Stop a node (stop it serving): bare stops your own node, `--at <peer>` stops a peer's.
#[derive(Debug, Args)]
pub struct StopCmd {
    /// the peer to reach: a petname (`alice`, `alice/desk`), a raw node id, or a `sheer:` link
    #[arg(long, value_name = "peer")]
    pub at: Option<Peer>,
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

    /// `stop --at` reaches the peer's family-gated `control.stop` service, so it presents the member badge
    /// rooted at the dialing key (only a family member may stop the node). `Family` fuses the identity to
    /// `PersistedIfPresent`. The effective slip is the FOLD of a self-addressing `sheer:` link in the `--at`
    /// peer with an explicit `--present`, threaded INTO the credential so the ONE resolver owns both slots.
    fn credential(&self) -> crate::credential::Credential {
        crate::credential::Credential::Family {
            present: self
                .at
                .as_ref()
                .and_then(Peer::self_present)
                .or_else(|| self.present.clone()),
        }
    }

    fn reject_redundant_present(&self) -> eyre::Result<()> {
        match &self.at {
            Some(peer) => peer.reject_redundant_present(self.present.as_ref()),
            None => Ok(()),
        }
    }

    fn identity(&self) -> crate::identity::Identity {
        self.credential().identity()
    }

    /// Uniform dispatch: unpack the reach context and run. `stop --at` reads the resolved `present` badge and
    /// `contacts` (to resolve a petname like `me/qat` in its `--at` slot); it ignores `transport` and `key`.
    /// Only reached WITH `--at`: a bare `stop` splits to [`run_local`](Self::run_local) before any transport
    /// is composed, so `at` is always `Some` here.
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
    /// The bare (no-`--at`) path: resolve YOUR OWN node's local control client and stop it over the
    /// socket. Runs BEFORE any transport is composed (dispatched locally in the root), so a bare
    /// `swoosh stop` never binds an endpoint it would not use. With no addressable resident the
    /// client resolution teaches the fix (`swoosh serve --resident`) and exits non-zero, never a
    /// silent success.
    pub async fn run_local(self, home: &Home) -> eyre::Result<()> {
        // A bare `stop` reaches no peer, so an explicit `--present` has nothing to select: refuse it
        // rather than silently dropping it (I.3), before touching the socket.
        crate::reaching::reject_bare_present(self.present.as_ref())?;
        let client = ControlClient::resolve(home).map_err(control_error_report)?;
        Self::stop_resolved(&client).await
    }

    /// The resolved-client half of [`run_local`](Self::run_local): stop, then confirm with the pid
    /// the client read from the resident's lock at resolve. Split from the resolve so a test drives
    /// the verb against the local socket backend without resolving the process-global runtime root.
    async fn stop_resolved(client: &ControlClient) -> eyre::Result<()> {
        let pid = client.pid();
        client.stop().await.map_err(control_error_report)?;
        println!("{}", stop_line(pid));
        Ok(())
    }

    /// Reach the peer's member-only `control.stop` service and trigger a graceful stop. Presents the
    /// resolved `present` (the self-signed membership badge, or an explicit `--present` link) so the gate
    /// rules on the stream; only a whole-node member passes the route's member floor, and a node that does
    /// not admit this caller refuses LOUDLY here, never a silent no-op. `--at` is required to reach this
    /// path (a bare `stop` split to [`run_local`](Self::run_local)), so a missing target is a root-dispatch
    /// bug, surfaced as an internal error rather than a user one.
    async fn run_stop<T: Transport, D: Discovery>(
        self,
        node: &Node<T, D>,
        contacts: &Contacts,
        present: Option<Link>,
        membership: Option<Link>,
    ) -> eyre::Result<()> {
        let Some(peer) = self.at else {
            eyre::bail!(
                "internal: `stop` reached the reach path without `--at` (root-dispatch bug)"
            );
        };

        // Slots 1 and 2 are ALREADY resolved by the composition root's ONE resolver (present-or-badge in
        // slot 1, a fleet badge in slot 2 only for a signet-bound slip); the fold in `credential()` routed a
        // link-as-peer through that same resolver, and the redundant-present conflict was rejected there too
        // (`Reaching::reject_redundant_present`), so the verb never threads `--present` itself.
        let connector = peer.connector(
            contacts,
            CONTROL_STOP_SERVICE.parse::<Service>()?,
            present,
            membership,
        )?;
        let dial = connector.dial();
        println!("stopping {dial}...");

        // A service-scoped session whose one `open_bi` speaks the `control.stop` request and presents the
        // badge. On admission the node cancels its teardown token and writes one ack byte; a refusal maps to
        // a loud stream error here (the false-success fix: a refusal is a typed loud error, never silent).
        let session = connector.open_service(node).await?;
        let (writer, mut reader) = match session.open_bi().await {
            Ok(stream) => stream,
            // The stream-open can lose the race with the very teardown the request triggered: the node
            // cancels its token, closes its endpoint, and this side sees a transport failure instead of the
            // torn ack tolerated below. A refusal is a LIVE peer saying no, so it is never raced away; any
            // other failure probes for the peer going down, and the original error stands if it stays live.
            Err(error) => {
                if matches!(error, bifrost::Error::Refused(_))
                    || !peer_gone(node, dial, STOP_PROBE_WINDOW).await
                {
                    return Err(eyre::eyre!("could not stop {dial}: {error}"));
                }
                println!("stopped {dial}.");
                node.close().await;
                return Ok(());
            }
        };

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

/// Whether `dial` is unreachable (gone, or mid-teardown) over `window`: the liveness probe that tells a
/// lost teardown race from a live peer. A successful connect at ANY point means the peer is still live, so
/// it returns `false` immediately (the caller must not report a false success); a window with no successful
/// connect means the peer is gone, so it returns `true`. The probe session is dropped at once: this is a
/// liveness read, never a second stop attempt.
async fn peer_gone<T: Transport, D: Discovery>(
    node: &Node<T, D>,
    dial: NodeId,
    window: Duration,
) -> bool {
    let probing = async {
        loop {
            if node.connect(dial).await.is_ok() {
                return false;
            }
            tokio::time::sleep(STOP_PROBE_INTERVAL).await;
        }
    };
    // The window bounds the probe: a peer that never accepts a connect (a hung dial included) counts as
    // gone, which is the state the caller asked for.
    tokio::time::timeout(window, probing).await.unwrap_or(true)
}

/// The one line a completed self-stop prints. The pid comes from the resident's `control.lock` read
/// at resolve (the same record the single-instance refusal names), so the line proves WHICH process
/// answered; a lock the resident had not written yet leaves the parenthetical off rather than
/// printing a blank or a guess.
fn stop_line(pid: Option<u32>) -> String {
    match pid {
        Some(pid) => format!("stopped your node (pid {pid})."),
        None => "stopped your node.".to_owned(),
    }
}

#[cfg(test)]
#[path = "stop_tests.rs"]
mod stop_tests;
