//! `swoosh forward <machine> <service> <port | unix:<path> | ->`: the generic dial. Bind a machine's served
//! service to a local port, stream it to stdout, or (reserved) a local unix listener.
//!
//! The MAIN ROAD. Most services get no verb of their own: a client that only moves bytes between the
//! stream and a file descriptor the user named is a pipe, not a program, and a pipe never earns a verb.
//! So this is the front door for every byte-shaped service: `swoosh forward me/nas db 5432` is the
//! `ssh -L` case, and `swoosh forward me/nas logs -` puts the stream on stdout, to compose with the shell.
//!
//! All three slots are POSITIONAL and REQUIRED, because none is ever optional and a slot that is never
//! optional is a positional. The local end has no default: nothing defaults to the terminal and nothing
//! defaults to the served port, so every form states where the bytes go. A missing local end is a usage
//! error that names the three ([`NO_LOCAL_END`]), found at parse, before anything is opened or bound.
//!
//! Drives tightbeam's tunnel wire under swoosh's OWN identity, through the one
//! [`connect`](crate::commands::connect::connect) runner, selected here by the single [`To`]. It is also
//! what `swoosh ssh` re-invokes as its `ProxyCommand` (`forward <peer> <service> -`), so the bridge is a
//! verb an operator can run by hand to debug a launch that fails.

use bifrost::{Discovery, Node, Transport};
use clap::Args;
use nauthy::Service;
use swoosh::peer::Peer;
use swoosh::transport::ReachArgs;

use crate::commands::connect::{To, connect};
use crate::commands::machine;

/// A machine's served service, forwarded to the local end it names.
#[derive(Debug, Args)]
pub struct ForwardCmd {
    #[arg(value_name = "machine", help = machine::HELP)]
    pub peer: Peer,
    /// the served service to reach, under the name the host bound it
    #[arg(value_name = "service", value_parser = swoosh::names::service)]
    pub service: Service,
    /// where the bytes go: a local port, `unix:<path>`, or `-` for stdout
    // Never defaulted (see the module docs). The id is named so the composition root can tell a line
    // missing only this slot from one missing anything else, and print the three ends for it.
    #[arg(id = LOCAL_END, value_name = "port | unix:<path> | -")]
    pub to: To,
    #[command(flatten)]
    pub reach: ReachArgs,
}

/// The local end's argument id, which the composition root makes optional for its second parse.
pub const LOCAL_END: &str = "local-end";

/// The refusal for a `forward` typed with no local end: a usage error (exit 2) naming the three ends. It
/// names neither the machine nor the service: a short key or a link's short form echoed back would read
/// as a command to copy, and neither runs.
pub const NO_LOCAL_END: &str =
    "forward needs a local end: a port (5432), unix:<path>, or - for stdout";

impl swoosh::reaching::Reaching for ForwardCmd {
    fn reach_args(&self) -> &swoosh::transport::ReachArgs {
        &self.reach
    }

    /// The peer this verb dials, for the stale-list exchange after it runs.
    fn dialed(&self) -> Option<&swoosh::peer::Peer> {
        Some(&self.peer)
    }

    fn identity(&self) -> swoosh::identity::Identity {
        self.bind_role().identity()
    }

    /// Dialing, and what it dials as. It reaches a peer and never accepts connections under the home key,
    /// so its bind must not write the key's address record (0.9.0 F1).
    ///
    /// `forward` reaches a family-gated service like every other reach-outward verb, so it presents the
    /// member badge rooted at the dialing key: a member reaching a service on their OWN node is admitted
    /// by their own fleet. Stating `Family` FUSES the identity to `PersistedIfPresent`, so the self-badge
    /// roots at the key the dial binds under. A self-addressing `swoosh:` link-as-peer is threaded INTO the
    /// credential so the ONE resolver owns both slots (slot 1 link-or-badge, slot 2 the fleet badge for a
    /// signet-bound slip).
    ///
    /// An `anyone` link typed as the peer presents alone, under a throwaway key (`Credential::dialing`).
    fn bind_role(&self) -> swoosh::reaching::BindRole {
        swoosh::reaching::BindRole::Dialing(swoosh::credential::Credential::dialing(
            &self.peer,
            self.service.as_str(),
        ))
    }

    /// Drive the local end: bind a local port and forward each connection, stream to stdout, or the
    /// reserved unix listener, all over the overlay. It reads the resolved `present` badge and `membership`
    /// badge from `ctx`, and the machine resolved before the bind, the same way `ping`/`send` do.
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
        // capped this dial at bearer slips.
        let Some(machine) = ctx.machine else {
            eyre::bail!("internal: `forward` ran without its machine resolved (root-dispatch bug)");
        };
        connect(
            node,
            ctx.contacts,
            machine,
            self.service,
            ctx.present,
            ctx.membership,
            self.to,
        )
        .await
    }
}
