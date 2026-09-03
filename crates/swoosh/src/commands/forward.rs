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

use crate::commands::tunnel_connect::{self, To};
use crate::credential::SheerLink;
use crate::peer::Peer;
use crate::transport::ReachArgs;

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
    /// present a `sheer:` cap link to a cap-gated peer (a delegate's slip)
    #[arg(
        long,
        value_name = "link",
        long_help = "Optional. `forward` dials as a stranger by construction (it never presents this \
                     node's identity), so pass a `sheer:` slip to reach a cap-gated service."
    )]
    pub present: Option<SheerLink>,
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

    fn reject_redundant_present(&self) -> eyre::Result<()> {
        self.peer.reject_redundant_present(self.present.as_ref())
    }

    fn identity(&self) -> crate::identity::Identity {
        self.credential().identity()
    }

    /// Drive the sink `--to` names: bind a local port and forward each connection, stream to stdout, or the
    /// reserved unix listener, all over the overlay. A dial-only client presenting its own `--present`
    /// link (it is `Anonymous`), so it reads only `contacts` from `ctx`, to resolve a petname in its peer
    /// slot the same way `ping`/`beam` do.
    async fn run<T: Transport, D: Discovery>(
        self,
        node: &Node<T, D>,
        ctx: crate::reaching::ReachCtx<'_>,
    ) -> eyre::Result<()>
    where
        <T::Session as bifrost::Session>::Write: Send + 'static,
        <T::Session as bifrost::Session>::Read: Send + 'static,
    {
        // The redundant-present conflict is rejected ONCE in the composition root via
        // `Reaching::reject_redundant_present`, before this runs.
        // `forward` is `Anonymous`, so `resolve()` yields no slots; it computes its effective slot 1 the same
        // way every verb does now: the peer's OWN link (a `sheer:` link-as-peer) folded with an explicit
        // `--present`, so a link-as-peer and a `--present` link flow through ONE path (defect #2: `forward`
        // no longer hand-threads a raw slot 1 divergent from the family verbs). Slot 2 is always empty: a
        // dial-only client presents its own link, never a fleet badge to AND.
        let slot1 = self
            .peer
            .self_present()
            .or_else(|| self.present.clone())
            .map(SheerLink::into_link);
        tunnel_connect::connect(
            node,
            ctx.contacts,
            &self.peer,
            self.service,
            slot1,
            None,
            self.to,
        )
        .await
    }
}
