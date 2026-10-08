//! `swoosh forward <peer> <service> <port | unix:<path> | ->`: the generic dial. Bind a machine's served
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
//! error that names the three, found before anything is opened or bound.
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

/// The `forward` command line as clap parses it. The local end is required, so `--help` shows it so; the
/// composition root parses a line missing only it once more with it optional, so the one refusal that
/// names the machine and the service is printed instead of clap's own. [`local_end`](Self::local_end)
/// turns it into the [`ForwardCmd`] that runs, which always has one.
#[derive(Debug, Args)]
pub struct ForwardArgs {
    /// the machine to reach: a petname (`alice`, `alice/desk`), a raw node id, or a `swoosh:` link
    #[arg(value_name = "peer")]
    pub peer: Peer,
    /// the served service to reach, under the name the host bound it
    #[arg(value_name = "service", value_parser = swoosh::names::service)]
    pub service: Service,
    /// where the bytes go: a local port, `unix:<path>`, or `-` for stdout
    // `Option` only so the refusal can name what was typed: clap's own "required argument" line cannot
    // carry the machine and the service. Never defaulted (see the module docs).
    #[arg(id = LOCAL_END, value_name = "port | unix:<path> | -", required = true)]
    pub end: Option<To>,
    #[command(flatten)]
    pub reach: ReachArgs,
}

/// The local end's argument id, which the composition root makes optional for its second parse.
pub const LOCAL_END: &str = "local-end";

impl ForwardArgs {
    /// The forward to run, or the refusal when no local end was given.
    pub fn local_end(self) -> Result<ForwardCmd, NoLocalEnd> {
        match self.end {
            Some(to) => Ok(ForwardCmd {
                peer: self.peer,
                service: self.service,
                to,
                reach: self.reach,
            }),
            None => Err(NoLocalEnd {
                peer: self.peer,
                service: self.service,
            }),
        }
    }
}

/// A `forward` typed with no local end. A usage error (exit 2): the command is incomplete, and the line
/// names the three ends it can take.
#[derive(Debug, thiserror::Error)]
#[error(
    "swoosh forward {peer} {service} needs a local end: a port (5432), unix:<path>, or - for stdout."
)]
pub struct NoLocalEnd {
    /// The machine as typed.
    peer: Peer,
    /// The service as typed.
    service: Service,
}

/// A machine's served service, forwarded to the local end it names.
#[derive(Debug)]
pub struct ForwardCmd {
    /// The machine to reach.
    pub peer: Peer,
    /// The served service to reach.
    pub service: Service,
    /// Where the bytes go.
    pub to: To,
    /// The reach-family flags.
    pub reach: ReachArgs,
}

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
        // capped this dial at bearer slips.
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
