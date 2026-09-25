//! `swoosh reach <peer> <service> [--to <port | - | unix:PATH>]`: the generic dial. Stream a peer's
//! served service to stdout, bind it to a local port, or (reserved) a local unix listener.
//!
//! The MAIN ROAD. Most services get no verb of their own: a client that only moves bytes between the
//! stream and a file descriptor the user named is a pipe, not a program, and a pipe never earns a verb.
//! So this is the front door for every byte-shaped service, and the common case takes no flags at all:
//! `swoosh reach alice echo` puts the stream on stdout, to compose with the shell.
//!
//! Both slots are POSITIONAL because neither is ever optional, and a flag that is never optional is a
//! positional in costume. `--to` is a SINK, not a mode: it says WHERE the bytes go (a local port, the
//! default `-` for stdout, a reserved `unix:PATH`), never whether to dial.
//!
//! Drives tightbeam's tunnel [`Connector`] under swoosh's OWN identity, through the one
//! [`connect`](crate::commands::connect::connect) runner, selected here by the single [`To`]. It is also
//! what `swoosh ssh` re-invokes as its `ProxyCommand` (`reach <key> <service> --to -`), so the bridge is
//! a verb an operator can run by hand to debug a launch that fails.

use bifrost::{Discovery, Node, Transport};
use clap::Args;
use nauthy::{Link, Service};
use swoosh::peer::Peer;
use swoosh::transport::ReachArgs;

use crate::commands::connect::{To, connect};

/// Reach a peer's served service: stdout by default, or `--to <port>`.
#[derive(Debug, Args)]
pub struct ReachCmd {
    /// the peer to reach: a petname (`alice`, `alice/desk`), a raw node id, or a `swoosh:` link
    #[arg(value_name = "peer")]
    pub peer: Peer,
    /// the served service to reach, under the name the host bound it
    // Positional and REQUIRED, with no default. It was `--service <name> [default: default]`, a name
    // nothing serves: tightbeam dropped the default service name, and the single-service leniency cannot
    // stand in for it because a bare `swoosh serve` binds TWO services. So a zero-config dial refused with
    // a message that named nothing. A slot the user must always fill is a positional, and an absent one is
    // now clap's own "required argument" error rather than a refusal at the far gate.
    #[arg(value_name = "service", value_parser = swoosh::names::service)]
    pub service: Service,
    /// where to put the stream: a local port, `-` for stdout, or `unix:<path>`
    // Defaults to stdout: the generic dial's common case is a pipe, so the flagless form is the good one.
    #[arg(long, value_name = "port | - | unix:PATH", default_value = "-")]
    pub to: To,
    /// present a `swoosh:` capability link to reach a gated peer
    #[arg(
        long,
        value_name = "link",
        value_parser = swoosh::link::parse,
        long_help = "Optional. `reach` presents this node's membership badge by default, so your own \
                     devices admit it. Pass a `swoosh:` link to reach a peer that granted you one instead."
    )]
    pub present: Option<Link>,
    #[command(flatten)]
    pub reach: ReachArgs,
}

impl swoosh::reaching::Reaching for ReachCmd {
    fn reach_args(&self) -> &swoosh::transport::ReachArgs {
        &self.reach
    }

    fn reject_redundant_present(&self) -> eyre::Result<()> {
        self.peer.reject_redundant_present(self.present.as_ref())
    }

    fn identity(&self) -> swoosh::identity::Identity {
        self.bind_role().identity()
    }

    /// Dialing, and what it dials as. It reaches a peer and never accepts connections under the home key,
    /// so its bind must not write the key's address record (0.9.0 F1).
    ///
    /// `reach` reaches a family-gated service like every other reach-outward verb, so it presents the
    /// member badge rooted at the dialing key: a member reaching a service on their OWN node is admitted
    /// by their own fleet. Stating `Family` FUSES the identity to `PersistedIfPresent`, so the self-badge
    /// roots at the key the dial binds under. The effective slip is the FOLD of a self-addressing `swoosh:`
    /// link-as-peer with an explicit `--present`, threaded INTO the credential so the ONE resolver owns
    /// both slots (slot 1 present-or-badge, slot 2 the fleet badge for a signet-bound slip).
    fn bind_role(&self) -> swoosh::reaching::BindRole {
        swoosh::reaching::BindRole::Dialing(swoosh::credential::Credential::Family {
            present: self.peer.self_present().or_else(|| self.present.clone()),
        })
    }

    /// Drive the sink `--to` names: stream to stdout, bind a local port and forward each connection, or the
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
        // capped this dial at bearer slips. The redundant-present conflict is rejected once at the root via
        // `Reaching::reject_redundant_present`, before this runs.
        connect(
            node,
            ctx.contacts,
            &self.peer,
            self.service,
            ctx.present,
            ctx.membership,
            self.to,
        )
        .await
    }
}
