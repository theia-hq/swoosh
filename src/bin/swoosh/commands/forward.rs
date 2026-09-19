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
use nauthy::{Link, Service};
use swoosh::peer::Peer;
use swoosh::transport::ReachArgs;

use crate::commands::tunnel_connect::{self, To};

/// Bind a peer's served service to a local port, stream it to stdout, or a reserved unix listener.
#[derive(Debug, Args)]
pub struct ForwardCmd {
    /// the peer to reach: a petname (`alice`, `alice/desk`), a raw node id, or a `sheer:` link
    #[arg(value_name = "peer")]
    pub peer: Peer,
    /// where to put the stream: a local port, `-` for stdout, or `unix:<path>`
    #[arg(long, value_name = "port | - | unix:PATH")]
    pub to: To,
    /// which served service to reach
    #[arg(long, value_name = "service", default_value = "default")]
    pub service: String,
    /// present a `sheer:` capability link to reach a gated peer
    #[arg(
        long,
        value_name = "link",
        long_help = "Optional. `forward` presents this node's membership badge by default, so your own \
                     devices admit it. Pass a `sheer:` link to reach a peer that granted you one instead."
    )]
    pub present: Option<Link>,
    #[command(flatten)]
    pub reach: ReachArgs,
}

impl swoosh::reaching::Reaching for ForwardCmd {
    fn reach_args(&self) -> &swoosh::transport::ReachArgs {
        &self.reach
    }

    fn reject_redundant_present(&self) -> eyre::Result<()> {
        self.peer.reject_redundant_present(self.present.as_ref())
    }

    fn identity(&self) -> swoosh::identity::Identity {
        self.bind_role().identity()
    }

    /// Dialing, and what it dials as. It reaches a peer and never accepts connections under the
    /// home key, so its bind must not write the key's address record (0.9.0 F1).
    ///
    /// `forward` reaches a family-gated service like every other reach-outward verb, so it presents the
    /// member badge rooted at the dialing key: a member forwarding a port on their OWN node is admitted
    /// by their own fleet. Stating `Family` FUSES the identity to `PersistedIfPresent`, so the self-badge
    /// roots at the key the dial binds under. The effective slip is the FOLD of a self-addressing `sheer:`
    /// link-as-peer with an explicit `--present`, threaded INTO the credential so the ONE resolver owns
    /// both slots (slot 1 present-or-badge, slot 2 the fleet badge for a signet-bound slip).
    fn bind_role(&self) -> swoosh::reaching::BindRole {
        swoosh::reaching::BindRole::Dialing(swoosh::credential::Credential::Family {
            present: self.peer.self_present().or_else(|| self.present.clone()),
        })
    }

    /// Drive the sink `--to` names: bind a local port and forward each connection, stream to stdout, or the
    /// reserved unix listener, all over the overlay. It reads the resolved `present` badge and `membership`
    /// badge from `ctx`, plus `contacts` to resolve a petname in its peer slot, the same way `ping`/`send` do.
    async fn run<T: Transport, D: Discovery>(
        self,
        node: &Node<T, D>,
        ctx: swoosh::reaching::ReachCtx<'_>,
    ) -> eyre::Result<()>
    where
        <T::Session as bifrost::Session>::Write: Send + 'static,
        <T::Session as bifrost::Session>::Read: Send + 'static,
    {
        // Both slots come from the composition root's ONE resolver, like every other reaching verb: a
        // hand-rolled slot 1 here could only re-derive what `resolve` already computed, and the hand-rolled
        // one silently dropped slot 2 (the resolver is the only code that computes it), which is what
        // capped `forward` at bearer slips. The redundant-present conflict is rejected once at the root via
        // `Reaching::reject_redundant_present`, before this runs.
        tunnel_connect::connect(
            node,
            ctx.contacts,
            &self.peer,
            self.service.parse::<Service>()?,
            ctx.present,
            ctx.membership,
            self.to,
        )
        .await
    }
}
