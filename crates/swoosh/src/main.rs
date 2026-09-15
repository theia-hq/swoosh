//! swoosh: work with a machine addressed by its public key, not its address.
//!
//! You give swoosh a peer's public key and it dials that peer directly, wherever the peer is on the
//! internet, across NATs, without you knowing the peer's address: no lookup, no server in the middle.
//! From that one connection swoosh does whatever you ask of the machine: today it stays reachable and
//! measures the link; as it grows, the same primitive carries files, tunnels, shared access, and
//! fetches. Under the hood every job is one cap-gated byte-stream to a key, behind a thin front door
//! per job, so the surface is broad while the core stays one thing.
//!
//! Today's verbs: `swoosh serve` prints this machine's key and stays reachable; `swoosh ping <peer>`
//! measures the round-trip time to a key; `swoosh speed <peer>` measures throughput; `swoosh status
//! <peer>` reports whether the link is direct or relayed; `swoosh contact add alice <key>` saves a
//! petname so `swoosh ping alice` works; `swoosh tree` prints the command tree. A peer is a raw key or
//! a saved petname, interchangeably.
//!
//! Each command runs under a key of its own. `serve` must be reachable at one address, so it persists a
//! key and keeps a stable address across runs (and across transports: `--transport iroh|quirk|quirk+noise`
//! swaps the backend without changing the key). The outward verbs only dial out, so they mint a throwaway
//! key each run unless you pin a home with `--home`/`SWOOSH_HOME` (the key then lives at `<home>/identity.key`).
//! The full verb arc (send, tunnel, share, fetch, run, cluster, MagicDNS names) is tracked in the README's
//! Roadmap; it ticks as it ships.

use std::path::PathBuf;

use bifrost::{Discovery, Node, Transport};
use clap::{Args, CommandFactory, Parser, Subcommand};
use nauthy::Link;
// The verb modules live in the swoosh LIBRARY (`lib.rs`), so an integration test can drive the same pieces
// this binary composes. The binary owns only the CLI surface below (the clap tree and composition root).
use swoosh::commands::adopt::AdoptCmd;
use swoosh::commands::contact::ContactCmd;
use swoosh::commands::fetch::FetchCmd;
use swoosh::commands::fleet::FleetCmd;
use swoosh::commands::forward::ForwardCmd;
use swoosh::commands::grant::GrantCmd;
use swoosh::commands::identity::IdentityCmd;
use swoosh::commands::invite::InviteCmd;
use swoosh::commands::ping::PingCmd;
use swoosh::commands::send::SendCmd;
use swoosh::commands::serve::ServeCmd;
use swoosh::commands::service::{ServiceCmd, ServiceLsCmd, ServiceToggleCmd};
use swoosh::commands::speed::SpeedCmd;
use swoosh::commands::ssh::SshCmd;
use swoosh::commands::status::StatusCmd;
use swoosh::commands::stop::StopCmd;
use swoosh::commands::tree::TreeCmd;
use swoosh::commands::tunnel_connect::TunnelConnectCmd;
use swoosh::contacts::{Contacts, ContactsStore};
use swoosh::home::Home;
use swoosh::identity::Identity;
use swoosh::reaching::Reaching;
use swoosh::transport::{MdnsState, PeerHint};
use swoosh::{config, credential, identity, reaching, transport};

#[derive(Debug, Parser)]
#[command(
    name = "swoosh",
    version,
    about = "Work with a machine addressed by its public key: reach it, measure it, and more.",
    // A bare `swoosh` is a mistake, not a default action: print the full help and exit non-zero. This
    // must hold even with `SWOOSH_HOME` set, but an env-backed global `--home` counts as an arg to clap,
    // so `arg_required_else_help` would fall to a terse "subcommand required" line there instead of the
    // help. So the subcommand is `Option` and the no-verb case is handled in `run`, one behavior whether
    // or not the env var is set.
    arg_required_else_help = true
)]
struct Cli {
    /// the node home: key, contacts, trust (default `~/.config/swoosh`)
    // clap appends the `[env: SWOOSH_HOME=]` annotation itself from `env` below, so the help must NOT
    // spell the env var again (doing so double-prints it).
    #[arg(
        long = "home",
        id = "node-home",
        value_name = "dir",
        env = "SWOOSH_HOME",
        global = true
    )]
    home: Option<PathBuf>,
    /// Retired: the node is a DIRECTORY now, so `--key <file>` became `--home <dir>` (the key lives at
    /// `<home>/identity.key`). Kept hidden, with no env and no default, ONLY so a stale `--key` gets a
    /// teaching error that names the replacement, rather than clap's bare "unexpected argument". A clean
    /// break: it selects nothing, it just triggers the forward message in `run`.
    #[arg(
        long = "key",
        id = "retired-key",
        value_name = "file",
        hide = true,
        global = true
    )]
    retired_key: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Serve services on this machine; peers you admit reach them.
    Serve(ServeCmd),
    /// Stop a node (stop it serving): bare stops your own node, `--at <peer>` stops a peer's.
    Stop(StopCmd),
    /// Read, enable, or disable this node's services (`ls`/`enable`/`disable`; `ls --at <peer>` reads a peer).
    #[command(subcommand)]
    Service(ServiceCmd),
    /// Measure the round-trip time to a peer, addressed by a petname or their public key.
    Ping(PingCmd),
    /// Measure throughput to a peer: iperf, but over the overlay.
    Speed(SpeedCmd),
    /// Show your node's status, or a peer's connection path
    Status(StatusCmd),
    /// Mint a local URL that fetches an origin through a node you name.
    Fetch(FetchCmd),
    /// Put a peer's served service on a local port, stdout (`-`), or a unix socket (ssh's `-L`, keyed).
    Forward(ForwardCmd),
    /// Push a file or directory to a peer, verified end to end.
    #[command(name = "send")]
    Send(SendCmd),
    /// Learn your fleet: pull the signed roster from a coordination node and fold it into your contacts.
    Fleet(FleetCmd),
    /// Manage local petnames: add a device, record a person's fleet signet, list, and remove.
    #[command(subcommand)]
    Contact(ContactCmd),
    /// Print this node's identity (its NodeId), minting a key if there is none.
    Identity(IdentityCmd),
    /// Create, list, and cancel invites: one device per invite.
    #[command(subcommand)]
    Invite(InviteCmd),
    /// Adopt an invite: join a signet's family as this machine.
    Adopt(AdoptCmd),
    /// Retired: `mint` folded into `invite add`. Kept hidden ONLY so a stale invocation gets a teaching
    /// error that names the replacement, rather than clap's bare "unexpected argument".
    #[command(hide = true)]
    Mint(RetiredMintCmd),
    /// Reach a peer's sshd over the overlay; runs the system ssh.
    Ssh(SshCmd),
    /// Issue, list, narrow, or revoke `sheer:` capability links.
    #[command(subcommand)]
    Grant(GrantCmd),
    /// Print this command tree (spec vs binary).
    Tree(TreeCmd),
    /// The in-process ProxyCommand behind `swoosh ssh`: self-invoked via `current_exe()`, never typed.
    /// Hidden from help and `tree`: it is plumbing, not a user verb (see `commands::tunnel_connect`).
    #[command(hide = true)]
    TunnelConnect(TunnelConnectCmd),
}

/// The retired `mint` verb, kept hidden ONLY so a stale invocation gets a teaching error naming
/// `invite add` instead of clap's bare "unexpected argument" (the same clean-break shape the retired
/// `--key` uses). The catch-all positional swallows whatever follows (`mint laptop`, `mint --expires
/// 90d`), so the forward error always fires; the field is never read.
#[derive(Debug, Args)]
struct RetiredMintCmd {
    /// never read; present so any argument tail still parses and forwards
    #[arg(
        value_name = "args",
        num_args = 0..,
        trailing_var_arg = true,
        allow_hyphen_values = true,
        hide = true
    )]
    args: Vec<String>,
}

/// A verb that reaches a peer: it binds a transport and dials. Split from the local `contact` group,
/// which touches only the address book and never composes a transport.
enum Reach {
    Serve(ServeCmd),
    Ping(PingCmd),
    Speed(SpeedCmd),
    Status(StatusCmd),
    Fetch(FetchCmd),
    /// `swoosh forward`: bind a peer's served service to a local port. A dial-only client (it presents a
    /// link, not swoosh's identity), so it rides the reach path like the other reach-outward verbs.
    Forward(ForwardCmd),
    /// `swoosh send`: push files to a peer's gated `recv:` service. Presents a membership badge (like
    /// `ping`/`speed`), so it rides the reach path under the persisted identity when one exists.
    Send(SendCmd),
    /// `swoosh stop --at <peer>`: reach a peer's gated `control.stop` service and trigger a graceful stop.
    /// Presents a membership badge (like `ping`/`speed`/`send`), so it rides the reach path under the
    /// persisted identity when one exists. A bare `stop` (your own node) splits to a local report instead.
    Stop(StopCmd),
    /// `swoosh service ls --at <peer>`: reach a peer's gated `control.services` read and print its
    /// `SERVICE  GATE` table. Presents a membership badge (like `stop`), so it rides the reach path under
    /// the persisted identity when one exists. A bare `service ls` (your own node) splits to a local report.
    Service(ServiceLsCmd),
    /// `swoosh fleet --pull`: pull the signed fleet roster from a coordination node and hydrate contacts.
    /// Presents a membership badge (like `ping`/`send`) and needs the persisted identity (adopt first).
    Fleet(FleetCmd),
    TunnelConnect(TunnelConnectCmd),
}

impl Command {
    /// Split the parsed verb into the local `contact` group (no transport) or a reaching verb (binds
    /// one). The two paths diverge before any transport is composed, so `contact add` never spins up an
    /// endpoint it does not need.
    fn split(self) -> Verb {
        match self {
            Self::Contact(cmd) => Verb::Contact(cmd),
            Self::Identity(cmd) => Verb::Identity(cmd),
            Self::Invite(cmd) => Verb::Invite(cmd),
            Self::Adopt(cmd) => Verb::Adopt(cmd),
            Self::Mint(_) => Verb::RetiredMint,
            Self::Ssh(cmd) => Verb::Ssh(cmd),
            Self::Tree(cmd) => Verb::Tree(cmd),
            Self::Grant(cmd) => Verb::Grant(cmd),
            Self::TunnelConnect(cmd) => Verb::Reach(Reach::TunnelConnect(cmd)),
            Self::Forward(cmd) => Verb::Reach(Reach::Forward(cmd)),
            Self::Send(cmd) => Verb::Reach(Reach::Send(cmd)),
            Self::Fleet(cmd) => Verb::Reach(Reach::Fleet(cmd)),
            // `stop --at <peer>` reaches a peer's `control.stop`; a bare `stop` stops YOUR OWN node over
            // the local control socket. Split on `--at` here so the bare case runs WITHOUT composing a
            // transport it would never use, the same local dispatch `ssh`/`grant` take.
            Self::Stop(cmd) => match cmd.at {
                Some(_) => Verb::Reach(Reach::Stop(cmd)),
                None => Verb::Stop(cmd),
            },
            // The `service` group: `ls --at <peer>` reaches a peer's `control.services`; bare `ls` reads your
            // own node over the local control socket, and `enable`/`disable` are LOCAL file-writes on
            // `<home>/disabled`. Split each here so the local arms never compose a transport they would not use.
            Self::Service(cmd) => match cmd {
                ServiceCmd::Ls(ls) => match ls.at {
                    Some(_) => Verb::Reach(Reach::Service(ls)),
                    None => Verb::ServiceLs(ls),
                },
                ServiceCmd::Enable(toggle) => Verb::ServiceEnable(toggle),
                ServiceCmd::Disable(toggle) => Verb::ServiceDisable(toggle),
            },
            Self::Serve(cmd) => Verb::Reach(Reach::Serve(cmd)),
            Self::Ping(cmd) => Verb::Reach(Reach::Ping(cmd)),
            Self::Speed(cmd) => Verb::Reach(Reach::Speed(cmd)),
            // A bare `status` (no peer) queries YOUR OWN node over the control socket, the same local
            // grammar as bare `stop`/`service ls`; with a peer it reaches out and reports its path.
            // Split here so the bare case never composes a transport it would not use.
            Self::Status(cmd) => match cmd.peer {
                Some(_) => Verb::Reach(Reach::Status(cmd)),
                None => Verb::Status(cmd),
            },
            Self::Fetch(cmd) => Verb::Reach(Reach::Fetch(cmd)),
        }
    }
}

/// The three kinds of verb, once split: purely local, a launcher, or reaching outward over a transport.
enum Verb {
    /// Edits the address book; needs no transport.
    Contact(ContactCmd),
    /// Prints this node's identity; needs no transport and no store, only the home.
    Identity(IdentityCmd),
    /// Creates, lists, or cancels invites; needs the key (the signet) and the store, no transport.
    Invite(InviteCmd),
    /// Adopts an invite: writes the trust + badge (a derived invite also writes the identity); needs the
    /// home, no store or transport.
    Adopt(AdoptCmd),
    /// The retired `mint` verb: parsed only so a stale invocation reaches the forward error in `run`,
    /// never a clap "unexpected argument". The parsed arguments are discarded: the message names the
    /// replacement whatever was typed.
    RetiredMint,
    /// Reads the address book to resolve a peer, then execs the system `ssh` over the overlay. A launcher:
    /// it reaches a peer, but binds no transport of its own (tightbeam, run as ssh's `ProxyCommand`, does),
    /// so it dispatches beside the local verbs, off the store, before any transport is composed.
    Ssh(SshCmd),
    /// A bare `swoosh service ls` (no `--at`): read YOUR OWN node's live menu over the local control
    /// socket, no transport or store. With `--at` it is a reaching verb instead.
    ServiceLs(ServiceLsCmd),
    /// `swoosh service enable <svc>`: a LOCAL file-write on `<home>/disabled` (remove a name), no transport.
    ServiceEnable(ServiceToggleCmd),
    /// `swoosh service disable <svc>`: a LOCAL file-write on `<home>/disabled` (add a name), no transport.
    ServiceDisable(ServiceToggleCmd),
    /// A bare `swoosh stop` (no `--at`): stop YOUR OWN node over the local control socket, no transport
    /// or store. With `--at` it is a reaching verb instead.
    Stop(StopCmd),
    /// A bare `swoosh status` (no peer): querying your OWN node over the control socket needs no
    /// transport or store. With a peer it is a reaching verb instead.
    Status(StatusCmd),
    /// Prints the command tree; needs no transport and no store.
    Tree(TreeCmd),
    /// Mints, narrows, or revokes a `sheer:` capability link. `share` signs with the persisted key;
    /// `attenuate` and `revoke` are wholly offline. No leaf binds a transport or reads the address book.
    Grant(GrantCmd),
    /// Reaches a peer; binds a transport.
    Reach(Reach),
}

impl Reach {
    /// The identity this verb binds under, forwarded to each verb's [`Reaching::identity`] (the ONE place
    /// a verb states it). A thin dispatch like [`credential`](Self::credential): for the reach-outward
    /// verbs `identity()` derives from the credential (`Family -> PersistedIfPresent`,
    /// `Anonymous -> Ephemeral`), so identity and badge cannot disagree; `serve`/`tunnel-connect` declare
    /// `Persisted` explicitly there. An explicit `--home` still overrides either (see [`identity::resolve`]).
    fn identity(&self) -> Identity {
        match self {
            Self::Serve(cmd) => cmd.identity(),
            Self::Ping(cmd) => cmd.identity(),
            Self::Speed(cmd) => cmd.identity(),
            Self::Status(cmd) => cmd.identity(),
            Self::Fetch(cmd) => cmd.identity(),
            Self::Forward(cmd) => cmd.identity(),
            Self::Send(cmd) => cmd.identity(),
            Self::Stop(cmd) => cmd.identity(),
            Self::Service(cmd) => cmd.identity(),
            Self::Fleet(cmd) => cmd.identity(),
            Self::TunnelConnect(cmd) => cmd.identity(),
        }
    }

    /// The reach-family flags this verb carries (`--transport`, `--local`, `--peer`). Shared by every
    /// reaching verb and no local one, so they are flattened into each reach command rather than made a
    /// root global; the composition root reads them here to pick the backend, the bind mode, and the
    /// discovery seed.
    fn args(&self) -> &transport::ReachArgs {
        match self {
            Self::Serve(cmd) => &cmd.reach,
            Self::Ping(cmd) => &cmd.reach,
            Self::Speed(cmd) => &cmd.reach,
            Self::Status(cmd) => &cmd.reach,
            Self::Fetch(cmd) => &cmd.reach,
            Self::Forward(cmd) => &cmd.reach,
            Self::Send(cmd) => &cmd.reach,
            Self::Stop(cmd) => &cmd.reach,
            Self::Service(cmd) => &cmd.reach,
            Self::Fleet(cmd) => &cmd.reach,
            Self::TunnelConnect(cmd) => &cmd.reach,
        }
    }

    /// Attach the resolved [`serve::ExposeContext`] to the `serve` verb (a no-op for every other verb, which
    /// carries no expose context), so `serve` reads its OWN context at run time. Called once in the root
    /// after the context is cut (while the secret is still live), before dispatch. This is why the reach
    /// [`ReachCtx`] stays uniform: the one verb that needs more than the shared context gets it on ITSELF
    /// here, not as an `Option` field threaded through every verb's dispatch.
    fn attach_expose(self, expose: Option<swoosh::commands::serve::ExposeContext>) -> Self {
        match (self, expose) {
            (Self::Serve(cmd), Some(expose)) => Self::Serve(cmd.with_expose(expose)),
            // A non-serve verb resolves `expose` to `None` (see `expose_context`), so there is nothing to
            // attach; a `serve` with no context is a root bug caught at its own `run`, not here.
            (reach, _) => reach,
        }
    }

    /// Attach the composed discovery's live [`MdnsState`] to the `serve` verb (a no-op for every other
    /// verb), so `serve`'s banner reports the discovery that started instead of assuming one. Called
    /// once per bind, at the seam that composed discovery, beside
    /// [`attach_expose`](Self::attach_expose); a `serve` that reaches its banner without one is a root
    /// bug caught there, not here.
    fn attach_mdns(self, mdns: MdnsState) -> Self {
        match self {
            Self::Serve(cmd) => Self::Serve(cmd.with_mdns(mdns)),
            reach => reach,
        }
    }

    /// Run the selected verb against the composed node, dispatching to each verb's [`Reaching::run`] with
    /// ONE uniform [`ReachCtx`] (`cmd.run(node, ctx)`), not a per-verb argument-threading match. Every verb
    /// is generic over `Node<T, D>`, so this stays transport-blind: the concrete transport was chosen once,
    /// at the seam below. A verb reads the ctx fields it needs (`contacts` to resolve a petname, the
    /// `transport` label to report, the resolved `present` badge, the `home`) and ignores the rest; `serve`
    /// reads its own attached [`serve::ExposeContext`] instead.
    async fn run<T: Transport, D: Discovery>(
        self,
        node: &Node<T, D>,
        ctx: reaching::ReachCtx<'_>,
    ) -> eyre::Result<()>
    where
        <T::Session as bifrost::Session>::Write: Send + 'static,
        <T::Session as bifrost::Session>::Read: Send + 'static,
    {
        match self {
            Self::Serve(cmd) => cmd.run(node, ctx).await,
            Self::Ping(cmd) => cmd.run(node, ctx).await,
            Self::Speed(cmd) => cmd.run(node, ctx).await,
            Self::Status(cmd) => cmd.run(node, ctx).await,
            Self::Fetch(cmd) => cmd.run(node, ctx).await,
            Self::Forward(cmd) => cmd.run(node, ctx).await,
            Self::Send(cmd) => cmd.run(node, ctx).await,
            Self::Fleet(cmd) => cmd.run(node, ctx).await,
            Self::Stop(cmd) => cmd.run(node, ctx).await,
            Self::Service(cmd) => cmd.run(node, ctx).await,
            Self::TunnelConnect(cmd) => cmd.run(node, ctx).await,
        }
    }

    /// How this verb authenticates: forwards to each verb's [`Reaching::credential`], the ONE place a
    /// verb's auth need lives. A thin dispatch (each arm just calls the trait method), so unlike the old
    /// hand-synced `self_badge()`/`identity()` matches, there is nothing to keep in sync and no wildcard
    /// to forget an arm in: a new `Reach` variant that omits its arm here does not compile.
    fn credential(&self) -> credential::Credential {
        match self {
            Self::Serve(cmd) => cmd.credential(),
            Self::Ping(cmd) => cmd.credential(),
            Self::Speed(cmd) => cmd.credential(),
            Self::Status(cmd) => cmd.credential(),
            Self::Fetch(cmd) => cmd.credential(),
            Self::Forward(cmd) => cmd.credential(),
            Self::Send(cmd) => cmd.credential(),
            Self::Stop(cmd) => cmd.credential(),
            Self::Service(cmd) => cmd.credential(),
            Self::Fleet(cmd) => cmd.credential(),
            Self::TunnelConnect(cmd) => cmd.credential(),
        }
    }

    /// Reject a redundant `--present` alongside a self-addressing `sheer:` link peer, ONCE for every
    /// reaching verb: forwards to each verb's [`Reaching::reject_redundant_present`], the compiler-forced
    /// conflict check. A thin dispatch like [`credential`](Self::credential), so a new `Reach` variant that
    /// omits its arm does not compile, and the guard can never be forgotten in a verb's own `run`.
    fn reject_redundant_present(&self) -> eyre::Result<()> {
        match self {
            Self::Serve(cmd) => cmd.reject_redundant_present(),
            Self::Ping(cmd) => cmd.reject_redundant_present(),
            Self::Speed(cmd) => cmd.reject_redundant_present(),
            Self::Status(cmd) => cmd.reject_redundant_present(),
            Self::Fetch(cmd) => cmd.reject_redundant_present(),
            Self::Forward(cmd) => cmd.reject_redundant_present(),
            Self::Send(cmd) => cmd.reject_redundant_present(),
            Self::Stop(cmd) => cmd.reject_redundant_present(),
            Self::Service(cmd) => cmd.reject_redundant_present(),
            Self::Fleet(cmd) => cmd.reject_redundant_present(),
            Self::TunnelConnect(cmd) => cmd.reject_redundant_present(),
        }
    }

    /// The two credential slots to present when dialing, DERIVED from [`credential`](Self::credential) via
    /// the single [`resolve`](reaching::resolve) home of the `--present`-overrides-self-badge rule: slot 1
    /// the grant, slot 2 a membership badge for a signet-bound slip's AND. There is no wildcard
    /// `_ => Ok((None, None))`: a verb's badge is whatever its `Credential` resolves to, so a verb that
    /// reaches a family-gated service without a badge is unrepresentable (the fleet/fetch bug class).
    ///
    /// Computed here, in the composition root, because it needs the resolved secret before the transport
    /// consumes it. `Anonymous` resolves to no slots; `Family` resolves slot 2 to the STORED signet-signed
    /// badge, else the signet holder's self-sign, and slot 1 to a `--present` slip if given, else the same
    /// badge mirrored.
    async fn present_slots(
        &self,
        secret: &identity::Secret,
        home: &Home,
    ) -> eyre::Result<(Option<Link>, Option<Link>)> {
        Ok(reaching::resolve(self.credential(), secret, home)
            .await?
            .into_slots())
    }

    /// The exposer context `serve` needs, resolved before the secret is consumed by the transport bind:
    /// swoosh's ssh host seed (derived from the secret), the signet its default gate trusts,
    /// and the revocation denylist the gate honors. All read from swoosh's OWN store, the node home, so a
    /// swoosh node gates on the signet `swoosh adopt` set under the same `--home`. Every other verb returns
    /// `None`. Async because the signet and denylist are read from disk.
    ///
    /// Person-zero self-signet: a node with its OWN key but no PROVISIONED signet (no `adopt`) gates on its
    /// OWN identity key as the signet root, rather than failing "no signet to gate on". A node self-trusts:
    /// it admits its own self-signed member badge (rooted at this key) and any device/delegate it later
    /// signs from this root, and refuses a stranger (whose badge roots at some other key the gate never
    /// trusts). This is what lets a plain node answer its own gated `ping`/`speed` without `--public`. The
    /// EXPLICIT-signet path (an adopted device carrying a provisioned signet) is untouched: `load_signet`
    /// wins whenever a signet file exists, and only its ABSENCE falls back to self.
    async fn expose_context(
        &self,
        secret: &identity::Secret,
        contacts: &Contacts,
        home: &Home,
    ) -> eyre::Result<Option<swoosh::commands::serve::ExposeContext>> {
        match self {
            // `serve` drives the gated exposer, so it resolves the exposer context; every other verb
            // returns `None`. The roster is cut and signed HERE, where the secret is still live and the
            // contacts store is loaded, then handed to the serve verb (via `attach_expose`) as a pre-cut blob.
            Self::Serve(_) => Ok(Some(swoosh::commands::serve::ExposeContext {
                #[cfg(feature = "ssh")]
                host_seed: secret.ssh_host_seed(),
                #[cfg(not(feature = "ssh"))]
                host_seed: [0u8; 32],
                signet: Some(
                    config::load_signet(home)
                        .await?
                        .unwrap_or_else(|| secret.node_id()),
                ),
                denylist: nauthy::FileDenylist::load(home.revoked()).await?,
                // The live enable/disable oracle (delib-47): the running exposer consults it per stream, so a
                // `service disable`/`enable` written to `<home>/disabled` is honored with no restart. Loaded
                // here beside the denylist because both are home files the gate reads.
                enabled: tightbeam::enabled::FileDisabledList::load(home.disabled()).await?,
                roster_blob: std::sync::Arc::new(swoosh::commands::serve::cut_roster(
                    contacts, secret,
                )?),
                // The SAME home the root resolved once: the resident socket/lock derive from it, so a
                // `--resident` serve and its future control clients name the same paths by construction.
                home: home.clone(),
            })),
            _ => Ok(None),
        }
    }
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    // Print the error's message chain, not eyre's `Debug` form: returning `eyre::Result` from `main`
    // trails a source `Location:` (and a spantrace) that is noise to a user and reads as "go read our
    // source". `{:#}` renders the full `cause: cause` chain with no location; the backtrace stays behind
    // `RUST_BACKTRACE` for anyone debugging. See STYLE.md, Error handling.
    match run().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(report) => {
            eprintln!("Error: {report:#}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// The teaching error a stale `mint` invocation gets. `mint` folded into `invite add` (one create
/// surface); the hidden verb exists only so the message can name the replacement and its two cells,
/// rather than clap's bare "unexpected argument". A pure constructor so the message is unit-tested.
fn retired_mint_error() -> eyre::Report {
    eyre::eyre!(
        "`mint` is gone; use `invite add <label>` to derive a device identity, or `invite add <label> \
         --for <key>` to bind a key the device made"
    )
}

/// Error FORWARD if the retired `SWOOSH_KEY` env var is set (Phase 1a errored only the flag, so a stale env
/// was a silent no-op that could select the wrong identity). A pure function over the presence bit, so the
/// forward message is unit-tested without touching (and racing on) the process environment.
fn reject_retired_key_env(present: bool) -> eyre::Result<()> {
    if present {
        eyre::bail!(
            "`SWOOSH_KEY` is gone; use `SWOOSH_HOME` (the node is a directory; the key lives at \
             `$SWOOSH_HOME/identity.key`)"
        );
    }
    Ok(())
}

/// The default `RUST_LOG` directives: ERROR everywhere, INFO for the receive engine, so a stock
/// `swoosh serve` surfaces the structured event a pushed file emits when it lands (the 0.9 workaround
/// for the receiver line the engine consumption dropped; delib-63 arm A keeps the line default-on for
/// 0.9, and quiet gating the activity class lands with the post-0.9 reporting contract).
///
/// The ERROR baseline is SPELLED OUT, not left to the builder's default directive: once any directive
/// parses, `with_default_directive` is not applied, so a bare `transfer=info` would drop every error on
/// every other target (verified against tracing-subscriber 0.3.23). Deliberately a narrow per-target
/// directive, not a global INFO default: a global bump would put every dependency's info events on
/// default stderr, including a serving node's log.
const DEFAULT_LOG: &str = "error,transfer=info";

/// The subscriber filter: `RUST_LOG` when set, else the default directives. The ERROR default
/// directive still covers an empty or all-invalid `RUST_LOG`, where no directive parses. `parse_lossy`
/// never fails, so a malformed directive is ignored rather than aborting the binary.
fn log_filter(directives: Option<String>) -> tracing_subscriber::EnvFilter {
    tracing_subscriber::EnvFilter::builder()
        .with_default_directive(tracing_subscriber::filter::LevelFilter::ERROR.into())
        .parse_lossy(directives.unwrap_or_else(|| DEFAULT_LOG.to_owned()))
}

/// The real entry point, split from `main` so a failure prints its clean message chain rather than
/// eyre's `Debug` form (see the note in `main`).
async fn run() -> eyre::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(log_filter(
            std::env::var(tracing_subscriber::EnvFilter::DEFAULT_ENV).ok(),
        ))
        // Diagnostics ride stderr, never stdout: stdout is a verb's product (`swoosh fetch` writes the
        // body there) and the action's public log, so a log line must not interleave. The action holds
        // serve's stderr in a file and echoes it only on failure, redacted.
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();

    // The retired `--key` is a clean break, not a silent alias: a stale invocation gets a teaching error
    // that names the replacement (the node is a DIRECTORY now), checked before anything else so it fires
    // whatever verb (or no verb) follows. See the `retired_key` field on `Cli`.
    if cli.retired_key.is_some() {
        eyre::bail!(
            "`--key` is gone; pass `--home <dir>` (the key lives at `<home>/identity.key`)"
        );
    }

    // The retired `SWOOSH_KEY` env var is the SAME clean break as `--key`, and a silent no-op is the danger:
    // Phase 1a only errored the FLAG, so a stale `SWOOSH_KEY` in a shell profile would sit ignored while
    // `--home`/`SWOOSH_HOME` (or the default) quietly selected a DIFFERENT identity. Detect it here and error
    // FORWARD so a stale env can never silently pick the wrong node. Read directly (the field carries no `env`,
    // deliberately, so clap never binds it); presence alone is the error, whatever its value.
    reject_retired_key_env(std::env::var_os("SWOOSH_KEY").is_some())?;

    // No verb given (a bare `swoosh`, even with `SWOOSH_HOME` set): print the full help and exit non-zero,
    // the same way clap's own `arg_required_else_help` does (full help, non-zero exit, no `Error:` line).
    // See the note on `Cli` for why this is handled here rather than by that attribute alone.
    let Some(command) = cli.command else {
        let mut help = Cli::command();
        help.print_help()?;
        std::process::exit(2);
    };

    // The node home, resolved ONCE from `--home`/`SWOOSH_HOME` (else the default `~/.config/swoosh`): every
    // node path (identity key, signet, badge, contacts, denylist, ledger) derives from it, so a verb never
    // re-derives one and two verbs can never disagree on where the store is.
    let home = Home::resolve(cli.home)?;

    // Local verbs run here, before any transport is composed and (for `tree`) before the store is even
    // opened: `tree` is pure introspection over clap's own model, and `contact` only edits the address
    // book. A reaching verb falls through to bind a transport below.
    let reach = match command.split() {
        Verb::Tree(cmd) => return cmd.run(&Cli::command()),
        // A bare `swoosh service ls` (no `--at`): read your own node's live table over the local control
        // socket. Run it here, before any transport is composed, the same local dispatch the other
        // transport-free verbs take. With `--at` this verb fell through to the reach path above instead.
        Verb::ServiceLs(cmd) => return cmd.run_local(&home).await,
        // A bare `swoosh stop` (no `--at`): stop your own node over the control socket, here too, before
        // any transport is composed. With `--at` it fell through to the reach path above.
        Verb::Stop(cmd) => return cmd.run_local(&home).await,
        // A bare `swoosh status` (no peer): query your own node's live status over the control socket.
        // Same local dispatch as the bare `stop`/`service ls` arms; with a peer it is a reach verb.
        Verb::Status(cmd) => return cmd.run_local(&home).await,
        // `service enable`/`disable`: LOCAL file-writes on `<home>/disabled`, honored live by a running
        // `serve` via the mtime-watched oracle. Need only the home; bind no transport and touch no store.
        Verb::ServiceEnable(cmd) => return cmd.run_enable(&home),
        Verb::ServiceDisable(cmd) => return cmd.run_disable(&home),
        Verb::Contact(cmd) => {
            let store = ContactsStore::open(home.contacts()).await?;
            return cmd.run(store).await;
        }
        // Prints this node's NodeId (minting a key if absent). Needs only the home, not the store or
        // a transport, so it dispatches here beside the other local verbs.
        Verb::Identity(cmd) => return cmd.run(&home).await,
        // Creates/lists/cancels invites: `add` signs a badge with this node's key and records the
        // `me/<label>` contact plus a ledger row; `ls` reads the ledger and the labels; `rm` revokes the
        // recorded badge. Needs the key and the store, but binds no transport.
        Verb::Invite(cmd) => {
            let store = ContactsStore::open(home.contacts()).await?;
            return cmd.run(store, &home).await;
        }
        // Adopts an invite: a derived invite writes the device identity + signet + badge; a bound invite
        // keeps the home's identity and writes the signet + badge. Needs only the home; no store, no
        // transport.
        Verb::Adopt(cmd) => return cmd.run(&home).await,
        // `mint` folded into `invite add`: a hidden catch-all so any stale invocation gets a teaching
        // error naming the replacement, whatever arguments followed it.
        Verb::RetiredMint => return Err(retired_mint_error()),
        // The `grant` group: `share` signs a link with the persisted key; `attenuate`/`revoke` are wholly
        // offline. No leaf binds a transport, so the group dispatches here beside the local verbs rather
        // than falling through to the reach path; `issue --for` reads the address book to resolve a device.
        Verb::Grant(cmd) => {
            return match cmd {
                // `issue` and `revoke` read the address book (to resolve a `--for`/holder petname to a
                // device), so they open the store; neither binds a transport.
                GrantCmd::Issue(cmd) => {
                    let store = ContactsStore::open(home.contacts()).await?;
                    cmd.run(store, &home).await
                }
                GrantCmd::Revoke(cmd) => {
                    let store = ContactsStore::open(home.contacts()).await?;
                    cmd.run(store, &home).await
                }
                // `ls` reads only swoosh's own mint-log ledger, so it needs neither the store nor a transport.
                GrantCmd::Ls(cmd) => cmd.run(&home).await,
                GrantCmd::Narrow(cmd) => cmd.run(),
            };
        }
        // A launcher: read the store to resolve the peer, then hand off to the system `ssh` (which runs
        // tightbeam as its `ProxyCommand`). swoosh binds no transport here; on unix `run` execs and does
        // not return on success.
        Verb::Ssh(cmd) => {
            let store = ContactsStore::open(home.contacts()).await?;
            return cmd.run(store.contacts(), &home);
        }
        Verb::Reach(reach) => reach,
    };

    // The address book lives in the node home, `<home>/contacts.toml`. A reach verb reads it to resolve a
    // petname in its peer slot.
    let store = ContactsStore::open(home.contacts()).await?;

    // The verb decides its identity: `serve` persists so it is reachable at one address, the reach-
    // outward verbs mint a fresh ephemeral key, and an explicit `--home` pins either. Resolve it before
    // binding, since the secret is what the transport is bound under.
    let secret = identity::resolve(reach.identity(), &home).await?;
    let contacts = Contacts::clone(store.contacts());

    // The one and only place a concrete transport is named. Everything downstream speaks `bifrost`. The
    // same secret yields the same NodeId whether bound under iroh or quirk, which is what makes the
    // transport swap a swap and not a new node. The reach-family flags travel on the verb itself now, so
    // the backend and the dial hints are read off the chosen reaching verb, not a root global.
    let transport = reach.args().transport;
    let local = reach.args().local;
    let peers = reach.args().peer.clone();
    // Reject a redundant `--present` alongside a self-addressing `sheer:` link peer ONCE here, before any
    // dial, so the conflict is loud and compiler-forced for every verb (each states its own check via
    // `Reaching::reject_redundant_present`), never a per-verb one-liner a new verb could forget.
    reach.reject_redundant_present()?;
    // Resolve the membership badge to present BEFORE the secret is consumed by the transport bind: an
    // adopted device presents its STORED signet-signed badge (bound to this key, which the dial then binds
    // under, so the far gate's device-binding matches); the signet holder self-signs one against the same
    // key for the same reason. The exposer context (`serve`) is resolved before the bind too: its ssh
    // host seed derives from the secret before the bind consumes it.
    let (present, membership) = reach.present_slots(&secret, &home).await?;
    let expose = reach
        .expose_context(&secret, store.contacts(), &home)
        .await?;
    // Attach the resolved exposer context to the `serve` verb (a no-op otherwise), so `serve` reads its OWN
    // context and every verb dispatches through the uniform `ReachCtx` below.
    let reach = reach.attach_expose(expose);
    // The one uniform context every verb runs against: the badge is already resolved, so the dispatch is
    // `cmd.run(node, ctx)` per verb, not a per-verb argument-threading match.
    let ctx = reaching::ReachCtx {
        contacts: &contacts,
        transport,
        local,
        present,
        membership,
        home: &home,
    };
    match transport {
        // iroh self-discovers (n0 pkarr/DNS + relays) AND honors explicit hints: the composed
        // discovery feeds it the `--peer` addresses and any LAN peer heard over mDNS as direct
        // addresses, so a same-network dial goes straight there instead of relaying. With nothing
        // known locally the resolve is empty and iroh self-discovers exactly as before. `--local`
        // keeps the same arm and swaps the constructor: the persisted key, no n0, no relays.
        transport::Transport::Iroh => {
            let endpoint = match IrohBind::of(local) {
                IrohBind::N0 => {
                    bifrost_iroh::Endpoint::bind_with_secret(secret.into_bytes()).await?
                }
                IrohBind::Local => {
                    bifrost_iroh::Endpoint::bind_local_with_secret(secret.into_bytes()).await?
                }
            };
            let composed = PeerHint::discovery(&endpoint, peers);
            let node = Node::new(endpoint, composed.discovery);
            run_and_close(reach.attach_mdns(composed.mdns), &node, ctx).await
        }
        // quirk is direct-only with no internal discovery, so the composed discovery is its only way
        // to learn a peer's address: the `--peer` hints, plus any peer heard over mDNS on the LAN.
        transport::Transport::Quirk => {
            let endpoint = bifrost_quirk::Endpoint::bind_with_secret(secret.into_bytes()).await?;
            let composed = PeerHint::discovery(&endpoint, peers);
            let node = Node::new(endpoint, composed.discovery);
            run_and_close(reach.attach_mdns(composed.mdns), &node, ctx).await
        }
        // The sealed spelling: quirk under the wrapper, still one node under one key. The wrapper runs
        // its own Noise handshake over quirk's one stream and proves the peer's `NodeId`, so a
        // signet-rooted gate arms (where bare quirk refuses); both ends must spell `quirk+noise`, and a
        // bare quirk peer fails the wrapper tag with no fallback. One seed binds both layers, and
        // `Noise::new` refuses an inner bound under any other identity, so the two can never disagree.
        // The seed stays in a zeroizing wrapper until the constructor has taken its copy.
        transport::Transport::QuirkNoise => {
            let seed = zeroize::Zeroizing::new(secret.into_bytes());
            let endpoint = bifrost_quirk::Endpoint::bind_with_secret(*seed).await?;
            let endpoint = bifrost_noise::Noise::new(endpoint, *seed)?;
            let composed = PeerHint::discovery(&endpoint, peers);
            let node = Node::new(endpoint, composed.discovery);
            run_and_close(reach.attach_mdns(composed.mdns), &node, ctx).await
        }
    }
}

/// Which iroh constructor the bind selects, the flag's one mechanism. A named choice instead of an
/// inline `if local`, so the composition root's match has an arm per mode with no wildcard to fall
/// through, and the mapping is a pure value a unit test can pin without binding a socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IrohBind {
    /// The n0 default: discovery (pkarr/DNS) plus relays.
    N0,
    /// `--local`: the persisted key with no n0 discovery, no relays, and no NAT traversal.
    Local,
}

impl IrohBind {
    /// Map the `--local` bit to the constructor it selects.
    fn of(local: bool) -> Self {
        if local { Self::Local } else { Self::N0 }
    }
}

/// Run a reaching verb against the bound node, then CLOSE the node on the way out on EVERY path (a clean
/// return and an error alike). The composition root owns the node's lifetime, so teardown lives here in one
/// place for the whole reaching family: iroh's `Endpoint` logs a red "Aborting ungracefully" if it drops
/// without an awaited close, so a verb that binds iroh must close it before the node drops (quirk's close is
/// a no-op). One owner of teardown, so no verb re-implements it; `serve`'s own graceful-drain still returns
/// first, and this is the single close that follows it.
async fn run_and_close<T: Transport, D: Discovery>(
    reach: Reach,
    node: &Node<T, D>,
    ctx: reaching::ReachCtx<'_>,
) -> eyre::Result<()>
where
    <T::Session as bifrost::Session>::Write: Send + 'static,
    <T::Session as bifrost::Session>::Read: Send + 'static,
{
    let result = reach.run(node, ctx).await;
    node.close().await;
    result
}

#[cfg(test)]
mod tests {
    use bifrost::NodeId;
    use clap::Parser;

    use super::*;

    /// The cap verbs live ONLY under `grant`, never as flat top-level commands: `swoosh grant issue`
    /// resolves, and a bare `swoosh issue` is an unknown command, not a leaf.
    #[test]
    fn cap_verbs_resolve_under_grant_not_the_top_level() {
        let cli =
            Cli::try_parse_from(["swoosh", "grant", "issue", "ssh"]).expect("grant issue parses");
        assert!(matches!(
            cli.command,
            Some(Command::Grant(GrantCmd::Issue(_)))
        ));

        // The bare verbs are gone from the top level; clap rejects them as unknown subcommands.
        assert!(Cli::try_parse_from(["swoosh", "issue", "ssh"]).is_err());
        assert!(Cli::try_parse_from(["swoosh", "narrow", "sheer:x"]).is_err());
        assert!(Cli::try_parse_from(["swoosh", "revoke", "sheer:x"]).is_err());
    }

    /// I.2 (no aliases, one spelling per act): the five retired spellings do not resolve, and the
    /// canonical spelling of each act still does. The B3 removal (CLI-DESIGN section 5c), pinned so a
    /// convenience alias cannot reappear unnoticed.
    #[test]
    fn retired_aliases_do_not_resolve() {
        for argv in [
            vec!["swoosh", "id"],
            vec!["swoosh", "service", "list"],
            vec!["swoosh", "grant", "list"],
            vec!["swoosh", "contact", "list"],
            vec!["swoosh", "contact", "remove"],
        ] {
            assert!(
                Cli::try_parse_from(&argv).is_err(),
                "{argv:?} must not resolve: one spelling per act (I.2)"
            );
        }
        for argv in [
            vec!["swoosh", "identity"],
            vec!["swoosh", "service", "ls"],
            vec!["swoosh", "grant", "ls"],
            vec!["swoosh", "contact", "ls"],
            vec!["swoosh", "contact", "rm", "alice"],
        ] {
            assert!(
                Cli::try_parse_from(&argv).is_ok(),
                "{argv:?} is the canonical spelling and must resolve"
            );
        }
    }

    /// The `tunnel` noun is retired: its two leaves are now the flat top-level verbs `serve` (publish
    /// services) and `forward` (bind a peer's service to a local port). `swoosh tunnel ...` no longer
    /// resolves; `serve` and `forward` do.
    #[test]
    fn tunnel_is_gone_and_serve_and_forward_are_flat() {
        let peer = NodeId::from_ed25519_secret(&[2u8; 32]).to_string();

        // The retired noun and both old paths are unknown commands now.
        assert!(Cli::try_parse_from(["swoosh", "tunnel"]).is_err());
        assert!(Cli::try_parse_from(["swoosh", "tunnel", "expose", "ping=ping:"]).is_err());
        assert!(Cli::try_parse_from(["swoosh", "tunnel", "connect", &peer, "--to", "22"]).is_err());

        // `serve` is the primary publish verb: bare (default `ping` + `speed`) and with an
        // explicit service set.
        assert!(matches!(
            Cli::try_parse_from(["swoosh", "serve"])
                .expect("bare serve parses")
                .command,
            Some(Command::Serve(_))
        ));
        assert!(matches!(
            Cli::try_parse_from(["swoosh", "serve", "ssh=sshd:", "ping=ping:"])
                .expect("serve with services parses")
                .command,
            Some(Command::Serve(_))
        ));

        // `forward` is the flat forward verb; `--to` takes a port, `-` (stdout), or `unix:<path>`.
        for to in ["5432", "-", "unix:/run/x.sock"] {
            assert!(
                matches!(
                    Cli::try_parse_from(["swoosh", "forward", &peer, "--to", to])
                        .expect("forward parses each --to form")
                        .command,
                    Some(Command::Forward(_))
                ),
                "forward --to {to} should parse"
            );
        }
        // A bare path or a source-only scheme is a hard parse error, never a silent misparse.
        for bad in ["/tmp/out", "fifo:/tmp/x", "0"] {
            assert!(
                Cli::try_parse_from(["swoosh", "forward", &peer, "--to", bad]).is_err(),
                "forward --to {bad} must be rejected"
            );
        }
        // `--stdio` is gone: the old boolean no longer parses.
        assert!(
            Cli::try_parse_from(["swoosh", "forward", &peer, "--stdio"]).is_err(),
            "the retired --stdio boolean must not resolve"
        );
    }

    /// The hidden `tunnel-connect` ABI (the `swoosh ssh` ProxyCommand bridge) is internal plumbing, not a
    /// user verb: its subcommand name is unchanged, so the ssh re-invocation `<self> tunnel-connect <peer>
    /// --to -` keeps resolving even though the user-facing `tunnel` noun is gone.
    #[test]
    fn the_hidden_tunnel_connect_abi_is_intact() {
        let cli = Cli::try_parse_from([
            "swoosh",
            "tunnel-connect",
            &NodeId::from_ed25519_secret(&[1u8; 32]).to_string(),
            "--service",
            "ssh",
            "--to",
            "-",
        ])
        .expect("the hidden tunnel-connect ABI still resolves");
        assert!(matches!(cli.command, Some(Command::TunnelConnect(_))));
    }

    /// Person-zero self-signet: `serve` on a node with its OWN key but NO provisioned signet (an empty
    /// config dir, no `signet` file) resolves its gate root to the node's OWN id, not `None`. This is the
    /// seam that lets a plain node gate on itself rather than fail "no signet to gate on"; the security
    /// consequence (admit self, refuse a stranger) is proved end to end in `person_zero_self_signet.rs`.
    #[tokio::test]
    async fn serve_with_no_signet_gates_on_the_nodes_own_key() {
        let dir = std::env::temp_dir().join(format!("swoosh-person-zero-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create an empty config dir");
        let home = Home::resolve(Some(dir.clone())).expect("resolve an explicit home");

        // An in-memory secret standing in for the persisted identity; the home it points at has no signet.
        let secret = identity::Secret::ephemeral();
        let reach = match Cli::try_parse_from(["swoosh", "serve"])
            .expect("bare serve parses")
            .command
            .expect("serve is a command")
            .split()
        {
            Verb::Reach(reach) => reach,
            _ => panic!("serve splits to a reaching verb"),
        };

        let expose = reach
            .expose_context(&secret, &Contacts::default(), &home)
            .await
            .expect("expose context resolves")
            .expect("serve carries an expose context");
        assert_eq!(
            expose.signet,
            Some(secret.node_id()),
            "an unprovisioned node gates on its OWN key (person-zero self-signet), not None"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A real `sheer:` capability link, minted through the library so a parse test exercises the true
    /// boundary (a `Peer::Capability` arm), not a fake token a lenient parser would wave through.
    fn sheer_link() -> String {
        let work = nauthy::Identity::from_secret(&[3u8; 32]).expect("valid work secret");
        let fleet = nauthy::Identity::from_secret(&[4u8; 32])
            .expect("valid fleet secret")
            .verifying_key();
        nauthy::Link::mint_signet(
            &work,
            &"ssh".parse().expect("valid service"),
            fleet,
            core::time::Duration::from_secs(3600),
        )
        .expect("mint a sheer: link")
        .to_string()
    }

    /// Every DIALING verb takes a unified `<peer>`: a saved petname, a raw key, and a `sheer:` link all
    /// parse in its peer slot, uniform across `ping`/`speed`/`status`/`forward`/`send`/`stop --at`/
    /// `service ls --at`/`fetch --via`/`ssh`/`fleet --pull`. `stop` and `service ls` carry the peer on `--at`
    /// (bare acts on your own node); the rest carry it positionally.
    #[test]
    fn every_dialing_verb_takes_a_petname_a_key_and_a_link() {
        let key = NodeId::from_ed25519_secret(&[8u8; 32]).to_string();
        let link = sheer_link();
        for peer in ["alice", key.as_str(), link.as_str()] {
            let cases: [&[&str]; 10] = [
                &["swoosh", "ping", peer],
                &["swoosh", "speed", peer],
                &["swoosh", "status", peer],
                &["swoosh", "forward", peer, "--to", "5432"],
                &["swoosh", "send", "afile", peer],
                &["swoosh", "stop", "--at", peer],
                &["swoosh", "service", "ls", "--at", peer],
                &["swoosh", "fetch", "http://example.com/x", "--via", peer],
                &["swoosh", "ssh", peer],
                &["swoosh", "fleet", "--pull", peer],
            ];
            for argv in cases {
                assert!(
                    Cli::try_parse_from(argv).is_ok(),
                    "{argv:?} should accept the peer form {peer:?}"
                );
            }
        }
    }

    /// The `--peer` HINT flag still parses, now under its de-collided clap id `peer-hint`, alongside a
    /// verb's positional `<peer>` with no clap id collision.
    #[test]
    fn the_peer_hint_flag_still_parses() {
        let key = NodeId::from_ed25519_secret(&[8u8; 32]).to_string();
        let cli = Cli::try_parse_from([
            "swoosh",
            "ping",
            "alice",
            "--peer",
            &format!("{key}=127.0.0.1:9000"),
        ])
        .expect("the --peer hint parses under its new id peer-hint");
        assert!(matches!(cli.command, Some(Command::Ping(_))));
    }

    /// The sealed quirk spelling resolves: `--transport quirk+noise` selects the wrapped composition
    /// under the same identity, while bare `quirk` stays its own choice (the profile enforcement, not
    /// the parser, refuses it a rooted gate). The label is what `ping`/`status` print and a failed dial
    /// names.
    #[test]
    fn the_sealed_quirk_transport_spelling_resolves() {
        let sealed = Cli::try_parse_from(["swoosh", "ping", "alice", "--transport", "quirk+noise"])
            .expect("the sealed quirk spelling parses");
        assert!(matches!(
            sealed.command,
            Some(Command::Ping(PingCmd {
                reach: transport::ReachArgs {
                    transport: transport::Transport::QuirkNoise,
                    ..
                },
                ..
            }))
        ));
        assert_eq!(transport::Transport::QuirkNoise.name(), "quirk+noise");

        // The bare spelling is unchanged and a DIFFERENT choice: the enforcement refuses it a rooted
        // gate, it never silently resolves to the wrapper.
        let bare = Cli::try_parse_from(["swoosh", "ping", "alice", "--transport", "quirk"])
            .expect("the bare quirk spelling parses");
        assert!(matches!(
            bare.command,
            Some(Command::Ping(PingCmd {
                reach: transport::ReachArgs {
                    transport: transport::Transport::Quirk,
                    ..
                },
                ..
            }))
        ));
        assert_ne!(
            transport::Transport::Quirk,
            transport::Transport::QuirkNoise
        );

        // The default remains iroh.
        let defaulted = Cli::try_parse_from(["swoosh", "ping", "alice"])
            .expect("a bare ping parses on the default transport");
        assert!(matches!(
            defaulted.command,
            Some(Command::Ping(PingCmd {
                reach: transport::ReachArgs {
                    transport: transport::Transport::Iroh,
                    ..
                },
                ..
            }))
        ));
    }

    /// The `--local` flag is a reach-family bind knob: it parses on the reaching verbs (the dial half
    /// rides the same bind), nowhere else, and is accepted idempotently on the already-direct-only quirk
    /// spellings. Placement is the reach group's, not a root global's.
    #[test]
    fn the_local_flag_lives_on_the_reach_family_only() {
        let parsed = Cli::try_parse_from(["swoosh", "ping", "alice", "--local"])
            .expect("ping --local parses");
        assert!(matches!(
            parsed.command,
            Some(Command::Ping(PingCmd {
                reach: transport::ReachArgs { local: true, .. },
                ..
            }))
        ));

        // Accepted idempotently on the direct-only quirk spellings: the flag states a bind property
        // quirk already has, so it is a no-op, never a conflict refusal.
        for quirk in ["quirk", "quirk+noise"] {
            let cli = Cli::try_parse_from(["swoosh", "serve", "--local", "--transport", quirk])
                .unwrap_or_else(|err| panic!("serve --local --transport {quirk} parses: {err}"));
            assert!(matches!(
                cli.command,
                Some(Command::Serve(ServeCmd {
                    reach: transport::ReachArgs { local: true, .. },
                    ..
                }))
            ));
        }

        // Placement: the flag rides `ReachArgs`, so a root or a transport-free verb never takes it.
        assert!(
            Cli::try_parse_from(["swoosh", "--local", "serve"]).is_err(),
            "`--local` is not a root global"
        );
        assert!(
            Cli::try_parse_from(["swoosh", "identity", "--local"]).is_err(),
            "`identity` binds no transport"
        );
        assert!(
            Cli::try_parse_from(["swoosh", "contact", "ls", "--local"]).is_err(),
            "`contact ls` binds no transport"
        );
    }

    /// The flag's one mechanism is constructor selection: `--local` picks the persisted-minimal iroh
    /// bind, the unset bit the n0 default. A pure mapping, so the branch is covered without a socket,
    /// and the composition root's match has an arm per mode with no wildcard.
    #[test]
    fn the_local_flag_selects_the_local_iroh_constructor() {
        assert_eq!(IrohBind::of(false), IrohBind::N0);
        assert_eq!(IrohBind::of(true), IrohBind::Local);
    }

    /// `--local` is a bind knob, not an auth knob: it must not change what `serve` gates or what
    /// `--public` opens. The parsed shape carries the same opened set and the same credential/identity
    /// declaration as the unflagged serve; the flag never enters the gate path.
    #[test]
    fn the_local_flag_leaves_the_gate_and_public_shape_alone() {
        let cli = Cli::try_parse_from(["swoosh", "serve", "--local", "--public", "speed"])
            .expect("serve --local --public parses");
        let Some(Command::Serve(cmd)) = cli.command else {
            panic!("serve parses to the serve verb");
        };
        assert!(cmd.reach.local, "the flag is set");
        assert_eq!(
            cmd.public,
            vec!["speed".to_owned()],
            "--public names the same opened set"
        );
        assert!(
            matches!(cmd.credential(), credential::Credential::Anonymous),
            "serve still dials as no one"
        );
        assert_eq!(
            cmd.identity(),
            identity::Identity::Persisted,
            "serve still binds the persisted key"
        );
    }

    /// The one control grammar (delib-47): BARE `stop` splits to the local (own-node) path, `stop --at <peer>`
    /// to the reach path. The bare form takes NO positional peer (the old `stop <peer>` is retired).
    #[test]
    fn stop_bare_is_local_and_at_is_the_reach_path() {
        let key = NodeId::from_ed25519_secret(&[7u8; 32]).to_string();

        // Bare: parses, and splits to the local self-report verb (needs no transport).
        let bare = Cli::try_parse_from(["swoosh", "stop"]).expect("bare stop parses");
        assert!(matches!(
            bare.command.expect("a command").split(),
            Verb::Stop(_)
        ));

        // `--at <peer>`: splits to the reach path.
        let at = Cli::try_parse_from(["swoosh", "stop", "--at", &key]).expect("stop --at parses");
        assert!(matches!(
            at.command.expect("a command").split(),
            Verb::Reach(Reach::Stop(_))
        ));

        // The retired positional form no longer resolves (pre-1.0 clean break).
        assert!(
            Cli::try_parse_from(["swoosh", "stop", &key]).is_err(),
            "the retired `stop <peer>` positional must not resolve"
        );
    }

    /// The `service` group: `ls` splits bare-local vs `--at`-reach, and `enable`/`disable` are local leaves.
    /// The old flat `service --at <peer>` (a leaf, not a group) is retired.
    #[test]
    fn service_group_splits_ls_enable_disable() {
        let key = NodeId::from_ed25519_secret(&[6u8; 32]).to_string();

        let bare_ls = Cli::try_parse_from(["swoosh", "service", "ls"]).expect("service ls parses");
        assert!(matches!(
            bare_ls.command.expect("a command").split(),
            Verb::ServiceLs(_)
        ));

        let at_ls = Cli::try_parse_from(["swoosh", "service", "ls", "--at", &key])
            .expect("service ls --at parses");
        assert!(matches!(
            at_ls.command.expect("a command").split(),
            Verb::Reach(Reach::Service(_))
        ));

        let enable = Cli::try_parse_from(["swoosh", "service", "enable", "speed"])
            .expect("service enable parses");
        assert!(matches!(
            enable.command.expect("a command").split(),
            Verb::ServiceEnable(_)
        ));

        let disable = Cli::try_parse_from(["swoosh", "service", "disable", "speed"])
            .expect("service disable parses");
        assert!(matches!(
            disable.command.expect("a command").split(),
            Verb::ServiceDisable(_)
        ));

        // The retired flat leaf form no longer resolves: `service` is a group now, so a bare `--at` with no
        // subcommand is a parse error, and `enable`/`disable` never take `--at` (you never toggle a peer).
        assert!(
            Cli::try_parse_from(["swoosh", "service", "--at", &key]).is_err(),
            "the retired flat `service --at` must not resolve; it is `service ls --at` now"
        );
        assert!(
            Cli::try_parse_from(["swoosh", "service", "disable", "speed", "--at", &key]).is_err(),
            "`disable` never takes `--at`: you never remotely toggle a peer's service"
        );
    }

    /// The retired `SWOOSH_KEY` env var errors FORWARD (naming `SWOOSH_HOME`), never a silent no-op.
    #[test]
    fn a_set_swoosh_key_env_errors_forward() {
        let error = reject_retired_key_env(true).expect_err("a set SWOOSH_KEY is an error");
        let message = format!("{error:#}");
        assert!(
            message.contains("SWOOSH_KEY") && message.contains("SWOOSH_HOME"),
            "the error names the retired var and its replacement: {message}"
        );
        // An unset env is the ordinary path: no error.
        assert!(reject_retired_key_env(false).is_ok());
    }

    /// A synthetic callsite backing the probe metadata below. The filter's static target directives
    /// read only an event's target and level, so this callsite is never consulted; it exists because
    /// `FieldSet`'s only constructor takes one.
    struct ProbeCallsite;

    impl tracing::Callsite for ProbeCallsite {
        fn set_interest(&self, _interest: tracing::subscriber::Interest) {}
        fn metadata(&self) -> &tracing::Metadata<'_> {
            &PROBE_TRANSFER_INFO
        }
    }

    static PROBE_CALLSITE: ProbeCallsite = ProbeCallsite;

    /// Synthetic event metadata for the filter probes: the receive engine's target at the INFO level it
    /// raises to, plus a NON-transfer target at INFO and at ERROR for the scoping proof. `Metadata::new`
    /// is const, so each probe is a static.
    static PROBE_TRANSFER_INFO: tracing::Metadata<'static> =
        probe_meta("transfer", tracing::Level::INFO);
    static PROBE_OTHER_INFO: tracing::Metadata<'static> =
        probe_meta("swoosh", tracing::Level::INFO);
    static PROBE_OTHER_ERROR: tracing::Metadata<'static> =
        probe_meta("swoosh", tracing::Level::ERROR);

    const fn probe_meta(target: &'static str, level: tracing::Level) -> tracing::Metadata<'static> {
        tracing::Metadata::new(
            "swoosh-log-filter-probe",
            target,
            level,
            None,
            None,
            None,
            tracing::field::FieldSet::new(&[], tracing::callsite::Identifier(&PROBE_CALLSITE)),
            tracing::metadata::Kind::EVENT,
        )
    }

    /// Whether `filter` would surface a synthetic event carrying `meta`, with no subscriber installed
    /// and nothing emitted. The register-side verdict is `Interest::never` for a target the static
    /// directives do not enable, and `always` for one they do.
    fn filter_enables(
        filter: &tracing_subscriber::EnvFilter,
        meta: &'static tracing::Metadata<'static>,
    ) -> bool {
        use tracing_subscriber::Layer;

        !Layer::<tracing_subscriber::Registry>::register_callsite(filter, meta).is_never()
    }

    /// The default filter SCOPES per target, not just by level: `transfer=info` surfaces the receive
    /// engine's arrival INFO while a NON-transfer INFO stays filtered and a non-transfer ERROR still
    /// passes (the scoping a level hint alone cannot prove). An explicit `RUST_LOG` replaces the
    /// default. Quiet gating the activity class is the post-0.9 reporting contract, not wired here.
    #[test]
    fn the_log_filter_scopes_by_target() {
        use tracing_subscriber::filter::LevelFilter;

        // The stock posture (arm A): the arrival line is on, and the ERROR baseline still admits a
        // non-transfer ERROR while a non-transfer INFO never rides in on the raised ceiling.
        let default = log_filter(None);
        assert!(filter_enables(&default, &PROBE_TRANSFER_INFO));
        assert!(!filter_enables(&default, &PROBE_OTHER_INFO));
        assert!(filter_enables(&default, &PROBE_OTHER_ERROR));

        // The rendered default still SPELLS the ERROR baseline beside the transfer directive:
        // `with_default_directive` is not applied once the parse yields a directive, so `transfer=info`
        // alone would drop every other target's ERROR events.
        let rendered = default.to_string();
        assert!(
            rendered.contains("error") && rendered.contains("transfer=info"),
            "the default keeps the ERROR baseline beside the transfer directive: {rendered}"
        );
        assert_eq!(
            default.max_level_hint(),
            Some(LevelFilter::INFO),
            "the transfer directive raises the ceiling so the receive event is shown"
        );

        // `RUST_LOG` wins: `warn` silences the arrival line; an explicit transfer directive restores it.
        let warn = log_filter(Some("warn".to_owned()));
        assert_eq!(warn.max_level_hint(), Some(LevelFilter::WARN));
        assert!(!filter_enables(&warn, &PROBE_TRANSFER_INFO));
        assert!(filter_enables(&warn, &PROBE_OTHER_ERROR));
        assert!(filter_enables(
            &log_filter(Some(DEFAULT_LOG.to_owned())),
            &PROBE_TRANSFER_INFO
        ));
    }

    /// The `invite` group resolves its three leaves, and `--for` is the SHARED `GrantFor` grammar: a raw
    /// key and a `<person>/<device>` are devices, `fleet:` parses (refused at run time, not at parse), and
    /// a bare person is the shared teaching parse error.
    #[test]
    fn invite_group_parses_the_grant_for_grammar() {
        let key = NodeId::from_ed25519_secret(&[4u8; 32]).to_string();
        assert!(matches!(
            Cli::try_parse_from(["swoosh", "invite", "add", "desk"])
                .expect("invite add parses")
                .command,
            Some(Command::Invite(InviteCmd::Add(_)))
        ));
        assert!(matches!(
            Cli::try_parse_from(["swoosh", "invite", "ls"])
                .expect("invite ls parses")
                .command,
            Some(Command::Invite(InviteCmd::Ls(_)))
        ));
        assert!(matches!(
            Cli::try_parse_from(["swoosh", "invite", "rm", "desk"])
                .expect("invite rm parses")
                .command,
            Some(Command::Invite(InviteCmd::Rm(_)))
        ));

        for who in [key.as_str(), "alice/laptop", "fleet:alice"] {
            assert!(
                Cli::try_parse_from(["swoosh", "invite", "add", "desk", "--for", who]).is_ok(),
                "--for {who} parses through the shared GrantFor grammar"
            );
        }
        // A bare person is refused at parse by the shared widening guardrail, and `cluster:` stays the
        // reserved-not-built kind it is on `grant issue`.
        assert!(
            Cli::try_parse_from(["swoosh", "invite", "add", "desk", "--for", "alice"]).is_err(),
            "a bare person is the shared GrantFor teaching parse error"
        );
        assert!(
            Cli::try_parse_from(["swoosh", "invite", "add", "desk", "--for", "cluster:home"])
                .is_err(),
            "cluster: stays the shared reserved-kind parse error"
        );
    }

    /// `mint` is retired into `invite add`: the hidden verb still parses, so a stale invocation reaches
    /// the forward error that names both `invite add` cells, whatever arguments followed it.
    #[test]
    fn mint_is_hidden_and_forwards_to_invite_add() {
        for argv in [
            vec!["swoosh", "mint"],
            vec!["swoosh", "mint", "laptop"],
            vec!["swoosh", "mint", "laptop", "--expires", "365d"],
        ] {
            let cli = Cli::try_parse_from(&argv).expect("the retired mint still parses");
            assert!(
                matches!(cli.command, Some(Command::Mint(_))),
                "{argv:?} reaches the forward error, never a clap parse error"
            );
        }
        let message = format!("{:#}", retired_mint_error());
        assert!(
            message.contains("invite add") && message.contains("--for"),
            "the forward error names the replacement and both cells: {message}"
        );
    }

    /// The retired verb stays OFF the user surface: no help render or `swoosh tree` walk names a `mint`
    /// subcommand (the tree walk skips hidden subcommands). It still exists hidden, which the test above
    /// parses, so a stale invocation reaches the forward error instead of a clap parse error.
    #[test]
    fn the_retired_mint_verb_is_hidden_from_help_and_tree() {
        let root = Cli::command();
        assert!(
            root.get_subcommands()
                .filter(|cmd| !cmd.is_hide_set())
                .all(|cmd| cmd.get_name() != "mint"),
            "a visible `mint` subcommand must not render in help or tree"
        );
        assert!(
            root.get_subcommands()
                .any(|cmd| cmd.get_name() == "mint" && cmd.is_hide_set()),
            "the hidden catch-all still parses, so a stale invocation reaches the forward error"
        );
    }
}
