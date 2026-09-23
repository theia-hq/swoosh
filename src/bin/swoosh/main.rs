//! swoosh: work with a machine addressed by its public key, not its address.
//!
//! You give swoosh a peer's public key and it dials that peer directly, wherever the peer is on the
//! internet, across NATs, without you knowing the peer's address: no lookup, no account.
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
use swoosh::contacts::{Contacts, ContactsStore};
use swoosh::home::Home;
use swoosh::identity::Identity;
use swoosh::reaching::{BindRole, Reaching};
use swoosh::transport::{MdnsState, PeerHint};
use swoosh::{config, credential, reaching, transport};

// The verb modules this binary dispatches to, each its own tree beside the composition root. The
// library (`swoosh::`) keeps only the node engine and the domain modules the verbs drive.
use crate::commands::{
    adopt, contact, fetch, fleet, grant, identity, invite, ping, reach, send, serve, service,
    speed, ssh, status, stop, tree,
};

mod commands;

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
    Serve(serve::ServeCmd),
    /// Stop a node (stop it serving): your own, or a peer's with `--at`.
    Stop(stop::StopCmd),
    /// Read, enable, or disable this node's services (`ls`/`enable`/`disable`; `ls --at <peer>` reads a peer).
    #[command(subcommand)]
    Service(service::ServiceCmd),
    /// Measure the round-trip time to a peer, addressed by a petname or their public key.
    Ping(ping::PingCmd),
    /// Measure throughput to a peer: iperf, but over the overlay.
    Speed(speed::SpeedCmd),
    /// Show your node's status, or a peer's connection path
    Status(status::StatusCmd),
    /// Mint a local URL that fetches an origin through a node you name.
    Fetch(fetch::FetchCmd),
    /// Reach a peer's served service: stdout by default, or `--to <port>`.
    Reach(reach::ReachCmd),
    /// Push a file or directory to a peer, verified end to end.
    #[command(name = "send")]
    Send(send::SendCmd),
    /// Learn your fleet: pull the signed roster from a coordination node and fold it into your contacts.
    Fleet(fleet::FleetCmd),
    /// Manage local petnames: add a device, record a person's fleet signet, list, and remove.
    #[command(subcommand)]
    Contact(contact::ContactCmd),
    /// Print this node's identity (its NodeId), minting a key if there is none.
    Identity(identity::IdentityCmd),
    /// Create, list, and cancel invites: one device per invite.
    #[command(subcommand)]
    Invite(invite::InviteCmd),
    /// Adopt an invite: join a signet's family as this machine.
    Adopt(adopt::AdoptCmd),
    /// Retired: `mint` folded into `invite add`. Kept hidden ONLY so a stale invocation gets a teaching
    /// error that names the replacement, rather than clap's bare "unexpected argument".
    #[command(hide = true)]
    Mint(RetiredMintCmd),
    /// Reach a peer's sshd over the overlay; runs the system ssh.
    Ssh(ssh::SshCmd),
    /// Issue, list, narrow, or revoke `sheer:` capability links.
    #[command(subcommand)]
    Grant(grant::GrantCmd),
    /// Print this command tree (spec vs binary).
    Tree(tree::TreeCmd),
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

/// Declare the reaching verbs ONCE: the list below becomes both the [`Reach`] enum and its whole
/// [`Reaching`] impl, so a verb joins the reach family by adding one line rather than an arm in each of
/// six parallel matches. Six hand-written arm lists is the shape the retired `self_badge()` drifted in:
/// nothing keeps them in step but the author's eye, and a `_` wildcard in any one of them silently admits
/// a verb that never stated its auth need. Generated, the six cannot disagree, and a verb missing from the
/// list is a compile error at [`Command::split`] rather than a verb that reaches a gate carrying nothing.
///
/// Earned by that invariant, not by the keystrokes: the forwarding is mechanical, identical per arm, and
/// there is no way to express "these six matches share one arm list" in the type system, because
/// [`Reaching::run`] is generic over the transport and cannot be a `dyn` object.
macro_rules! reaching_verbs {
    ($($(#[$note:meta])* $verb:ident($cmd:ty)),+ $(,)?) => {
        /// A verb that reaches a peer: it binds a transport and dials. Split from the local `contact` group,
        /// which touches only the address book and never composes a transport.
        enum Outward {
            $($(#[$note])* $verb($cmd),)+
        }

        impl Reaching for Outward {
            /// The reach-family flags this verb carries (`--transport`, `--local`, `--peer`). Shared by every
            /// reaching verb and no local one, so they are flattened into each reach command rather than made
            /// a root global; the composition root reads them here to pick the backend, the bind mode, and
            /// the discovery seed.
            fn reach_args(&self) -> &transport::ReachArgs {
                match self {
                    $(Self::$verb(cmd) => cmd.reach_args(),)+
                }
            }

            /// Reject a redundant `--present` alongside a self-addressing `sheer:` link peer, ONCE for every
            /// reaching verb, so the guard can never be forgotten in a verb's own `run`.
            fn reject_redundant_present(&self) -> eyre::Result<()> {
                match self {
                    $(Self::$verb(cmd) => cmd.reject_redundant_present(),)+
                }
            }

            /// The identity this verb binds under. For the reach-outward verbs it derives from the bind
            /// role's credential (`Family -> PersistedIfPresent`), so identity and badge cannot disagree;
            /// `serve` declares `Persisted` explicitly, because a stable address is its whole job.
            fn identity(&self) -> Identity {
                match self {
                    $(Self::$verb(cmd) => cmd.identity(),)+
                }
            }

            /// What this verb's bind is for, and (when it dials) what it presents. Read BEFORE the bind,
            /// since it selects the iroh constructor: only `serve` publishes, so a short-lived command
            /// cannot overwrite the live record (0.9.0 F1), and only a dialing verb resolves slots.
            fn bind_role(&self) -> BindRole {
                match self {
                    $(Self::$verb(cmd) => cmd.bind_role(),)+
                }
            }

            /// Run the selected verb against the composed node with ONE uniform [`reaching::ReachCtx`], not
            /// a per-verb argument-threading match. Every verb is generic over `Node<T, D>`, so this stays
            /// transport-blind: the concrete transport was chosen once, at the seam below. A verb reads the
            /// ctx fields it needs and ignores the rest; `serve` reads its own attached
            /// [`serve::ExposeContext`] instead.
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
                    $(Self::$verb(cmd) => cmd.run(node, ctx).await,)+
                }
            }
        }
    };
}

reaching_verbs! {
    Serve(serve::ServeCmd),
    Ping(ping::PingCmd),
    Speed(speed::SpeedCmd),
    Status(status::StatusCmd),
    Fetch(fetch::FetchCmd),
    /// `swoosh reach`: the generic dial, any service, any sink. Presents a membership badge (like
    /// `ping`/`send`), which a `--present` slip overrides, so it rides the reach path under the persisted
    /// identity when one exists.
    Reach(reach::ReachCmd),
    /// `swoosh send`: push files to a peer's gated `recv:` service. Presents a membership badge (like
    /// `ping`/`speed`), so it rides the reach path under the persisted identity when one exists.
    Send(send::SendCmd),
    /// `swoosh stop --at <peer>`: reach a peer's gated `control.stop` service and trigger a graceful stop.
    /// Presents a membership badge (like `ping`/`speed`/`send`), so it rides the reach path under the
    /// persisted identity when one exists. A bare `stop` (your own node) splits to a local report instead.
    Stop(stop::StopCmd),
    /// `swoosh service ls --at <peer>`: reach a peer's gated `control.services` read and print its
    /// `SERVICE  GATE` table. Presents a membership badge (like `stop`), so it rides the reach path under
    /// the persisted identity when one exists. A bare `service ls` (your own node) splits to a local report.
    Service(service::ServiceLsCmd),
    /// `swoosh fleet <peer>`: pull the signed fleet roster from a coordination node and hydrate contacts.
    /// Presents a membership badge (like `ping`/`send`) and needs the persisted identity (adopt first).
    Fleet(fleet::FleetCmd),
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
            Self::Reach(cmd) => Verb::Outward(Outward::Reach(cmd)),
            Self::Send(cmd) => Verb::Outward(Outward::Send(cmd)),
            Self::Fleet(cmd) => Verb::Outward(Outward::Fleet(cmd)),
            // `stop --at <peer>` reaches a peer's `control.stop`; a bare `stop` stops YOUR OWN node over
            // the local control socket. Split on `--at` here so the bare case runs WITHOUT composing a
            // transport it would never use, the same local dispatch `ssh`/`grant` take.
            Self::Stop(cmd) => match cmd.at {
                Some(_) => Verb::Outward(Outward::Stop(cmd)),
                None => Verb::Stop(cmd),
            },
            // The `service` group: `ls --at <peer>` reaches a peer's `control.services`; bare `ls` reads your
            // own node over the local control socket, and `enable`/`disable` are LOCAL file-writes on
            // `<home>/disabled`. Split each here so the local arms never compose a transport they would not use.
            Self::Service(cmd) => match cmd {
                service::ServiceCmd::Ls(ls) => match ls.at {
                    Some(_) => Verb::Outward(Outward::Service(*ls)),
                    None => Verb::ServiceLs(*ls),
                },
                service::ServiceCmd::Enable(toggle) => Verb::ServiceEnable(toggle),
                service::ServiceCmd::Disable(toggle) => Verb::ServiceDisable(toggle),
            },
            Self::Serve(cmd) => Verb::Outward(Outward::Serve(cmd)),
            Self::Ping(cmd) => Verb::Outward(Outward::Ping(cmd)),
            Self::Speed(cmd) => Verb::Outward(Outward::Speed(cmd)),
            // A bare `status` (no peer) queries YOUR OWN node over the control socket, the same local
            // grammar as bare `stop`/`service ls`; with a peer it reaches out and reports its path.
            // Split here so the bare case never composes a transport it would not use.
            Self::Status(cmd) => match cmd.peer {
                Some(_) => Verb::Outward(Outward::Status(cmd)),
                None => Verb::Status(cmd),
            },
            Self::Fetch(cmd) => Verb::Outward(Outward::Fetch(cmd)),
        }
    }
}

/// The three kinds of verb, once split: purely local, a launcher, or reaching outward over a transport.
enum Verb {
    /// Edits the address book; needs no transport.
    Contact(contact::ContactCmd),
    /// Prints this node's identity; needs no transport and no store, only the home.
    Identity(identity::IdentityCmd),
    /// Creates, lists, or cancels invites; needs the key (the signet) and the store, no transport.
    Invite(invite::InviteCmd),
    /// Adopts an invite: writes the trust + badge (a derived invite also writes the identity); needs the
    /// home, no store or transport.
    Adopt(adopt::AdoptCmd),
    /// The retired `mint` verb: parsed only so a stale invocation reaches the forward error in `run`,
    /// never a clap "unexpected argument". The parsed arguments are discarded: the message names the
    /// replacement whatever was typed.
    RetiredMint,
    /// Reads the address book to resolve a peer, then execs the system `ssh` over the overlay. A launcher:
    /// it reaches a peer, but binds no transport of its own (tightbeam, run as ssh's `ProxyCommand`, does),
    /// so it dispatches beside the local verbs, off the store, before any transport is composed.
    Ssh(ssh::SshCmd),
    /// A bare `swoosh service ls` (no `--at`): read YOUR OWN node's live menu over the local control
    /// socket, no transport or store. With `--at` it is a reaching verb instead.
    ServiceLs(service::ServiceLsCmd),
    /// `swoosh service enable <svc>`: a LOCAL file-write on `<home>/disabled` (remove a name), no transport.
    ServiceEnable(service::ServiceToggleCmd),
    /// `swoosh service disable <svc>`: a LOCAL file-write on `<home>/disabled` (add a name), no transport.
    ServiceDisable(service::ServiceToggleCmd),
    /// A bare `swoosh stop` (no `--at`): stop YOUR OWN node over the local control socket, no transport
    /// or store. With `--at` it is a reaching verb instead.
    Stop(stop::StopCmd),
    /// A bare `swoosh status` (no peer): querying your OWN node over the control socket needs no
    /// transport or store. With a peer it is a reaching verb instead.
    Status(status::StatusCmd),
    /// Prints the command tree; needs no transport and no store.
    Tree(tree::TreeCmd),
    /// Mints, narrows, or revokes a `sheer:` capability link. `share` signs with the persisted key;
    /// `attenuate` and `revoke` are wholly offline. No leaf binds a transport or reads the address book.
    Grant(grant::GrantCmd),
    /// Reaches a peer; binds a transport.
    Outward(Outward),
}

impl Outward {
    /// Attach the resolved [`serve::ExposeContext`] to the `serve` verb (a no-op for every other verb, which
    /// carries no expose context), so `serve` reads its OWN context at run time. Called once in the root
    /// after the context is cut (while the secret is still live), before dispatch. This is why the reach
    /// [`ReachCtx`] stays uniform: the one verb that needs more than the shared context gets it on ITSELF
    /// here, not as an `Option` field threaded through every verb's dispatch.
    fn attach_expose(self, expose: Option<serve::ExposeContext>) -> Self {
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

    /// Attach the composed [`transport::Reach`] to the `serve` verb (a no-op for every other verb), so
    /// its banner names the relay it offers and the resolver it publishes to instead of promising n0's.
    /// Called at the iroh arm only, beside [`attach_mdns`](Self::attach_mdns): every other bind leans on
    /// neither, and its banner says the same thing it always did.
    fn attach_bound_reach(self, bound: &transport::Reach) -> Self {
        match self {
            Self::Serve(cmd) => Self::Serve(cmd.with_bound_reach(transport::Reach::clone(bound))),
            verb => verb,
        }
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
        secret: &swoosh::identity::Secret,
        home: &Home,
    ) -> eyre::Result<Option<serve::ExposeContext>> {
        match self {
            // `serve` drives the gated exposer, so it resolves the exposer context; every other verb
            // returns `None`. The roster is not cut here (or anywhere in `serve`): the artifact was
            // signed by whichever verb last changed the membership, on the machine holding the signet,
            // so this path only OPENS it, beside the two other home oracles the gate reads.
            Self::Serve(_) => Ok(Some(serve::ExposeContext {
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
                // The live enable/disable oracle: the running exposer consults it per stream, so a
                // `service disable`/`enable` written to `<home>/disabled` is honored with no restart. Loaded
                // here beside the denylist because both are home files the gate reads.
                enabled: tightbeam::enabled::FileDisabledList::load(home.disabled()).await?,
                // The third home oracle, same read-on-demand shape as the two above, and `None` on a
                // node that does not hold the signet: such a node can never have a roster to serve, and
                // saying so at bind time is what the old self-signed cut hid. The oracle tolerates an
                // absent file, so the signet's machine may `serve roster:` before its first invite and
                // start serving the moment one is cut. Only an entry that actually names `roster:` acts
                // on the `None`, so an unrelated serve never fails on a roster concern.
                roster: if config::holds_signet(home, secret.node_id()).await? {
                    Some(std::sync::Arc::new(
                        swoosh::roster::Artifact::open(home.roster()).await?,
                    ))
                } else {
                    None
                },
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

/// The default `RUST_LOG` directive: ERROR everywhere. Activity lines do not ride the log at all (a
/// serving node renders them itself, and `--quiet` withholds them), so no target needs a raised default,
/// and a dependency's info events never reach a stock node's stderr.
const DEFAULT_LOG: &str = "error";

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
            return cmd.run(store, &home).await;
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
                grant::GrantCmd::Issue(cmd) => {
                    let store = ContactsStore::open(home.contacts()).await?;
                    cmd.run(store, &home).await
                }
                grant::GrantCmd::Revoke(cmd) => {
                    let store = ContactsStore::open(home.contacts()).await?;
                    cmd.run(store, &home).await
                }
                // `ls` reads only swoosh's own mint-log ledger, so it needs neither the store nor a transport.
                grant::GrantCmd::Ls(cmd) => cmd.run(&home).await,
                grant::GrantCmd::Narrow(cmd) => cmd.run(),
            };
        }
        // A launcher: read the store to resolve the peer, then hand off to the system `ssh` (which runs
        // tightbeam as its `ProxyCommand`). swoosh binds no transport here; on unix `run` execs and does
        // not return on success.
        Verb::Ssh(cmd) => {
            let store = ContactsStore::open(home.contacts()).await?;
            return cmd.run(store.contacts(), &home);
        }
        Verb::Outward(outward) => {
            // Before anything is opened or minted: a flag the selected bind would never read is refused
            // here, not after the store is loaded and a key provisioned, so a refused
            // `serve --local --relay` on a fresh home leaves that home exactly as it found it.
            outward.reach_args().reject_unused_reach()?;
            outward
        }
    };

    // The address book lives in the node home, `<home>/contacts.toml`. A reach verb reads it to resolve a
    // petname in its peer slot.
    let store = ContactsStore::open(home.contacts()).await?;

    // The verb decides its identity: `serve` persists so it is reachable at one address, a reach-outward
    // verb binds the home's key where one exists (its badge roots there) and a throwaway where none does,
    // writing nothing. Resolve it before binding, since the secret is what the transport is bound under.
    // A serving node holds the home lock for its whole life, taken before its key is read, so a restore
    // can never replace the key it is serving as.
    let _home_lock = match reach.identity() {
        Identity::Persisted => Some(swoosh::identity::HomeLock::serving(&home)?),
        Identity::Ephemeral | Identity::PersistedIfPresent => None,
    };
    let secret = swoosh::identity::resolve(reach.identity(), &home).await?;
    let contacts = Contacts::clone(store.contacts());

    // The one and only place a concrete transport is named. Everything downstream speaks `bifrost`. The
    // same secret yields the same NodeId whether bound under iroh or quirk, which is what makes the
    // transport swap a swap and not a new node. The reach-family flags travel on the verb itself now, so
    // the backend and the dial hints are read off the chosen reaching verb, not a root global.
    let transport = reach.reach_args().transport;
    let local = reach.reach_args().local;
    // The verb's bind role, read BEFORE the bind selects a constructor: only a `Serving` verb publishes
    // the home key's address record, so a dial-only command never overwrites the live `serve` record
    // (0.9.0 F1). It carries the dialing verb's credential too, so the one read below answers both what
    // this bind publishes and what it presents. Read here, before `reach` is consumed by dispatch.
    let bind_role = reach.bind_role();
    let peers = reach.reach_args().peer.clone();
    // What this run bound, as ONE value: every consumer (a verb reporting its backend, a failed dial's
    // teaching line, `serve`'s banner) reads all three facts, so they travel together from here. The
    // relay and the resolver come from the flags and the home files, over the ONE bind that reads them
    // (the guard at the arm above refused the flags on every other), so a stale file can never refuse a
    // quirk or `--local` bind that would not have opened it.
    let bound = transport::Bound {
        transport,
        local,
        reach: match reach.reach_args().unused_reach_bind() {
            Some(_unused) => transport::Reach::default(),
            None => {
                // Resolve BEFORE persisting: a malformed file or a refused flag must leave the home as
                // it found it, so a run that cannot compose its reach never writes one half of it.
                let composed = reach.reach_args().reach(&home).await?;
                // A serving verb OWNS the home, so the two servers it was pointed at become the home's
                // and every later verb under it reaches the same fleet with no flags repeated. A dialing
                // verb's flag is this run only, so it writes nothing.
                if matches!(bind_role, BindRole::Serving) {
                    reach.reach_args().persist_reach(&home).await?;
                }
                composed
            }
        },
    };
    // Reject a redundant `--present` alongside a self-addressing `sheer:` link peer ONCE here, before any
    // dial, so the conflict is loud and compiler-forced for every verb (each states its own check via
    // `Reaching::reject_redundant_present`), never a per-verb one-liner a new verb could forget.
    reach.reject_redundant_present()?;
    // Resolve the membership badge to present BEFORE the secret is consumed by the transport bind: an
    // adopted device presents its STORED signet-signed badge (bound to this key, which the dial then binds
    // under, so the far gate's device-binding matches); the signet holder self-signs one against the same
    // key for the same reason. The exposer context (`serve`) is resolved before the bind too: its ssh
    // host seed derives from the secret before the bind consumes it.
    //
    // The SERVING verb resolves nothing: it is the gate, so it presents no credential and never mints or
    // loads a badge it would not send. There is no wildcard here and no "present nothing" credential for a
    // dialing verb to reach for: the role it declared decides, and only one of its arms carries slots.
    let (present, membership) = match &bind_role {
        BindRole::Serving => (None, None),
        BindRole::Dialing(dial) => {
            reaching::resolve(credential::Credential::clone(dial), &secret, &home)
                .await?
                .into_slots()
        }
    };
    let expose = reach.expose_context(&secret, &home).await?;
    // Attach the resolved exposer context to the `serve` verb (a no-op otherwise), so `serve` reads its OWN
    // context and every verb dispatches through the uniform `ReachCtx` below.
    let reach = reach.attach_expose(expose);
    // The one uniform context every verb runs against: the badge is already resolved, so the dispatch is
    // `cmd.run(node, ctx)` per verb, not a per-verb argument-threading match.
    let ctx = reaching::ReachCtx {
        contacts: &contacts,
        bound: &bound,
        present,
        membership,
        home: &home,
    };
    // Each transport bind borrows the seed through `with_bytes` and returns a future that holds only
    // what it derived, so the seed never leaves its wiping owner.
    match transport {
        // iroh self-discovers (n0 pkarr/DNS + relays) AND honors explicit hints: the composed
        // discovery feeds it the `--peer` addresses and any LAN peer heard over mDNS as direct
        // addresses, so a same-network dial goes straight there instead of relaying. With nothing
        // known locally the resolve is empty and iroh self-discovers exactly as before. The verb's bind
        // role picks the n0 constructor (serving publishes the address record, dialing does not);
        // `--local` keeps the same arm and swaps in the persisted key with no n0, no relays.
        transport::Transport::Iroh => {
            let endpoint = match IrohBind::of(local, &bind_role) {
                IrohBind::Reachable => {
                    secret
                        .with_bytes(|seed| {
                            bifrost_iroh::Endpoint::bind_reachable_with_secret_via(
                                seed,
                                transport::Reach::clone(&bound.reach),
                            )
                        })
                        .await?
                }
                IrohBind::Dialing => {
                    secret
                        .with_bytes(|seed| {
                            bifrost_iroh::Endpoint::bind_dialing_with_secret_via(
                                seed,
                                transport::Reach::clone(&bound.reach),
                            )
                        })
                        .await?
                }
                IrohBind::Local => {
                    secret
                        .with_bytes(bifrost_iroh::Endpoint::bind_local_with_secret)
                        .await?
                }
            };
            let composed = PeerHint::discovery(&endpoint, peers);
            let node = Node::new(endpoint, composed.discovery);
            let reach = reach.attach_bound_reach(&bound.reach);
            run_and_close(reach.attach_mdns(composed.mdns), &node, ctx).await
        }
        // quirk is direct-only with no internal discovery, so the composed discovery is its only way
        // to learn a peer's address: the `--peer` hints, plus any peer heard over mDNS on the LAN.
        transport::Transport::Quirk => {
            let endpoint = secret
                .with_bytes(bifrost_quirk::Endpoint::bind_with_secret)
                .await?;
            let composed = PeerHint::discovery(&endpoint, peers);
            let node = Node::new(endpoint, composed.discovery);
            run_and_close(reach.attach_mdns(composed.mdns), &node, ctx).await
        }
        // The sealed spelling: quirk under the wrapper, still one node under one key. The wrapper runs
        // its own Noise handshake over quirk's one stream and proves the peer's `NodeId`, so a
        // signet-rooted gate arms (where bare quirk refuses); both ends must spell `quirk+noise`, and a
        // bare quirk peer fails the wrapper tag with no fallback. One seed binds both layers, and
        // `Noise::new` refuses an inner bound under any other identity, so the two can never disagree.
        transport::Transport::QuirkNoise => {
            let endpoint = secret
                .with_bytes(bifrost_quirk::Endpoint::bind_with_secret)
                .await?;
            let endpoint = secret.with_bytes(|seed| bifrost_noise::Noise::new(endpoint, seed))?;
            let composed = PeerHint::discovery(&endpoint, peers);
            let node = Node::new(endpoint, composed.discovery);
            run_and_close(reach.attach_mdns(composed.mdns), &node, ctx).await
        }
    }
}

/// Which iroh constructor the bind selects, the flags' one mechanism. A named choice instead of an
/// inline `if local`, so the composition root's match has an arm per mode with no wildcard to fall
/// through, and the mapping is a pure value a unit test can pin without binding a socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IrohBind {
    /// The n0 default under a SERVING verb: discovery (pkarr/DNS) plus relays, and the address-record
    /// write peers resolve.
    Reachable,
    /// The n0 default under a DIALING verb: the same resolvers and relays, no publisher, so a
    /// short-lived command never overwrites the live `serve` record (0.9.0 F1).
    Dialing,
    /// `--local`: the persisted key with no n0 discovery, no relays, and no NAT traversal.
    Local,
}

impl IrohBind {
    /// Map the `--local` bit and the verb's [`BindRole`] to the constructor they select. `--local` wins:
    /// it removes n0 entirely, so there is no discovery to resolve and no record to write either way.
    fn of(local: bool, role: &BindRole) -> Self {
        if local {
            Self::Local
        } else {
            match role {
                BindRole::Serving => Self::Reachable,
                BindRole::Dialing(_) => Self::Dialing,
            }
        }
    }
}

/// Run a reaching verb against the bound node, then CLOSE the node on the way out on EVERY path (a clean
/// return and an error alike). The composition root owns the node's lifetime, so teardown lives here in one
/// place for the whole reaching family: iroh's `Endpoint` logs a red "Aborting ungracefully" if it drops
/// without an awaited close, so a verb that binds iroh must close it before the node drops (quirk's close is
/// a no-op). One owner of teardown, so no verb re-implements it; `serve`'s own graceful-drain still returns
/// first, and this is the single close that follows it.
async fn run_and_close<T: Transport, D: Discovery>(
    outward: Outward,
    node: &Node<T, D>,
    ctx: reaching::ReachCtx<'_>,
) -> eyre::Result<()>
where
    <T::Session as bifrost::Session>::Write: Send + 'static,
    <T::Session as bifrost::Session>::Read: Send + 'static,
{
    let result = outward.run(node, ctx).await;
    node.close().await;
    result
}

// The CLI-surface proofs that drive a real verb (clap-parsed, exactly as the binary dispatches it):
// they live with the binary because they exercise its command types, and the library only sees the
// core those verbs call.
#[cfg(test)]
#[path = "grant_issue_fleet_tests.rs"]
mod grant_issue_fleet_tests;
#[cfg(test)]
#[path = "grant_revoke_refuses_tests.rs"]
mod grant_revoke_refuses_tests;
#[cfg(test)]
#[path = "signet_dial_verb_tests.rs"]
mod signet_dial_verb_tests;

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
            Some(Command::Grant(grant::GrantCmd::Issue(_)))
        ));

        // The bare verbs are gone from the top level; clap rejects them as unknown subcommands.
        assert!(Cli::try_parse_from(["swoosh", "issue", "ssh"]).is_err());
        assert!(Cli::try_parse_from(["swoosh", "narrow", "sheer:x"]).is_err());
        assert!(Cli::try_parse_from(["swoosh", "revoke", "sheer:x"]).is_err());
    }

    /// I.2 (no aliases, one spelling per act): the five retired spellings do not resolve, and the
    /// canonical spelling of each act still does. The retired alias stays retired, pinned so a
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
    /// services) and `reach` (the generic dial). `swoosh tunnel ...` no longer resolves; `serve` and
    /// `reach` do, and the `forward` spelling `reach` replaced is gone with the noun.
    #[test]
    fn tunnel_and_forward_are_gone_and_serve_and_reach_are_flat() {
        let peer = NodeId::from_ed25519_secret(&[2u8; 32]).to_string();

        // The retired noun and both old paths are unknown commands now.
        assert!(Cli::try_parse_from(["swoosh", "tunnel"]).is_err());
        assert!(Cli::try_parse_from(["swoosh", "tunnel", "expose", "ping=ping:"]).is_err());
        assert!(Cli::try_parse_from(["swoosh", "tunnel", "connect", &peer, "--to", "22"]).is_err());
        // `forward` is retired as a word: one spelling per act, and the act is `reach`.
        assert!(
            Cli::try_parse_from(["swoosh", "forward", &peer, "--to", "5432"]).is_err(),
            "the retired `forward` spelling must not resolve, not even as a hidden alias"
        );

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

        // `reach` is the flat generic dial; `--to` takes a port, `-` (stdout), or `unix:<path>`.
        for to in ["5432", "-", "unix:/run/x.sock"] {
            assert!(
                matches!(
                    Cli::try_parse_from(["swoosh", "reach", &peer, "web", "--to", to])
                        .expect("reach parses each --to form")
                        .command,
                    Some(Command::Reach(_))
                ),
                "reach --to {to} should parse"
            );
        }
        // A bare path or a source-only scheme is a hard parse error, never a silent misparse.
        for bad in ["/tmp/out", "fifo:/tmp/x", "0"] {
            assert!(
                Cli::try_parse_from(["swoosh", "reach", &peer, "web", "--to", bad]).is_err(),
                "reach --to {bad} must be rejected"
            );
        }
        // `--stdio` is gone: the old boolean no longer parses.
        assert!(
            Cli::try_parse_from(["swoosh", "reach", &peer, "web", "--stdio"]).is_err(),
            "the retired --stdio boolean must not resolve"
        );
    }

    /// The generic dial's two defaults, pinned: the SINK defaults to stdout, and the SERVICE has no
    /// default at all.
    ///
    /// Both halves fail if the guard is dropped. Re-add `default_value` to the service slot (the
    /// `default` ghost that shipped through v0.11.1, a name no `serve` binds) and the first assertion
    /// stops erroring; drop `default_value = "-"` from `--to` and the flagless form stops parsing. The
    /// pair is the whole shape ruled for `reach`: the common case takes no flags, and the slot the user
    /// must always fill is a positional clap refuses to invent.
    #[test]
    fn reach_requires_a_service_and_defaults_its_sink_to_stdout() {
        let peer = NodeId::from_ed25519_secret(&[2u8; 32]).to_string();

        assert!(
            Cli::try_parse_from(["swoosh", "reach", &peer]).is_err(),
            "the service slot is required: a dial with no service must be clap's own error here, \
             never a default name the far gate refuses without saying why"
        );
        assert!(
            Cli::try_parse_from(["swoosh", "reach", &peer, "--service", "web"]).is_err(),
            "the service is a positional, not a flag: `--service` is not a spelling of it"
        );

        let Some(Command::Reach(cmd)) = Cli::try_parse_from(["swoosh", "reach", &peer, "web"])
            .expect("the flagless form parses: peer, service, nothing else")
            .command
        else {
            panic!("`reach` parses to the reach verb");
        };
        assert_eq!(cmd.service.as_str(), "web");
        assert_eq!(
            cmd.to,
            commands::connect::To::Stdout,
            "the sink defaults to stdout, so the common case composes with the shell"
        );
    }

    /// `fleet` takes its coordination node POSITIONALLY, by the same rule that took `--service` off the
    /// generic dial: the slot is mandatory and sole, and the verb has no own-node form, so a long flag
    /// was a positional wearing a costume. It shipped as `fleet --pull <peer>` through v0.11.2.
    ///
    /// Each assertion inverts, and the negatives come first so the failure names the regression. Put
    /// `long` back on the peer slot and the first goes red (`--pull` starts parsing again); give the slot
    /// a `default_value` (or make it `Option<Peer>`) and the second goes red (a bare `fleet` stops being
    /// clap's own missing-argument error and becomes a verb with no object); either edit takes the third,
    /// because the flagless form is the only thing both spellings cannot share.
    #[test]
    fn fleet_takes_its_coordination_node_as_a_positional() {
        assert!(
            Cli::try_parse_from(["swoosh", "fleet", "--pull", "me/hub"]).is_err(),
            "the coordination node is a positional, not a flag: `--pull` is not a spelling of it"
        );
        assert!(
            Cli::try_parse_from(["swoosh", "fleet"]).is_err(),
            "the peer slot is required: a pull with no coordination node is clap's own error, never \
             a verb that dials nothing"
        );

        let Some(Command::Fleet(cmd)) = Cli::try_parse_from(["swoosh", "fleet", "me/hub"])
            .expect("the flagless form parses: the verb and its object, nothing else")
            .command
        else {
            panic!("`fleet` parses to the fleet verb");
        };
        assert_eq!(cmd.peer.to_string(), "me/hub");
    }

    /// The `swoosh ssh` ProxyCommand ABI, which is now the PUBLIC `reach` verb: ssh re-invokes
    /// `<self> reach <key> <service> --to -`, so the exact line that carries an ssh session is one an
    /// operator can run by hand to debug a launch that fails. It was a hidden leaf whose argv nothing
    /// else could type, and the leaf differed from `reach` in one observable: it declared
    /// `Identity::Persisted`, so a FAILED dial from an unprovisioned home minted the key a later
    /// `serve` would gate its whole fleet on.
    ///
    /// This is the PARSING half of that ABI; `ssh_argv`'s tests are the writing half. Every token the
    /// launcher may append rides one line, in the order it writes them: the global `--home`, the
    /// `--present` slip, then one `--peer <key>=<addr>` per hint.
    #[test]
    fn the_ssh_proxycommand_line_parses_as_a_public_reach() {
        let peer = NodeId::from_ed25519_secret(&[1u8; 32]).to_string();
        let link = sheer_link();
        let hint = format!("{peer}=127.0.0.1:9000");
        let cli = Cli::try_parse_from([
            "swoosh",
            "reach",
            &peer,
            "ssh",
            "--to",
            "-",
            "--home",
            "/tmp/yah",
            "--present",
            &link,
            "--peer",
            &hint,
        ])
        .expect("the ProxyCommand line parses as a reach");
        assert_eq!(cli.home, Some(PathBuf::from("/tmp/yah")));
        let Some(Command::Reach(cmd)) = cli.command else {
            panic!("the ProxyCommand line is a `reach`");
        };
        assert_eq!(cmd.service.as_str(), "ssh");
        assert_eq!(
            cmd.to,
            commands::connect::To::Stdout,
            "the bridge streams the single service over stdin/stdout"
        );
        assert_eq!(
            cmd.present.as_ref().map(nauthy::Link::as_str),
            Some(link.as_str())
        );
        assert_eq!(cmd.reach.peer.len(), 1, "each `--peer` hint rides verbatim");

        // The retired spelling is gone: a stale `swoosh ssh` launched from an older binary's config, or
        // a hand-typed guess, gets clap's unknown-subcommand error rather than a hidden verb.
        assert!(
            Cli::try_parse_from([
                "swoosh",
                "tunnel-connect",
                &peer,
                "--service",
                "ssh",
                "--to",
                "-"
            ])
            .is_err(),
            "the hidden bridge leaf is gone; `reach` is the one spelling of this act"
        );
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
        let secret = swoosh::identity::Secret::ephemeral();
        let outward = match Cli::try_parse_from(["swoosh", "serve"])
            .expect("bare serve parses")
            .command
            .expect("serve is a command")
            .split()
        {
            Verb::Outward(outward) => outward,
            _ => panic!("serve splits to a reaching verb"),
        };

        let expose = outward
            .expose_context(&secret, &home)
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

    /// The composition root decides ONCE whether this node may serve a roster, and it decides it on the
    /// signet, not on whether a file happens to exist.
    ///
    /// A member device gets `None` (so naming `roster:` is refused at bind, loudly, instead of
    /// advertising a service every puller must reject, which is what the old self-signed cut did
    /// silently). The signet's own machine gets the oracle even with nothing cut yet, so it may serve
    /// before its first invite and start serving the moment one lands.
    #[tokio::test]
    async fn only_the_signets_machine_carries_a_roster_to_serve() {
        let dir = std::env::temp_dir().join(format!("swoosh-roster-ctx-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create an empty config dir");
        let home = Home::resolve(Some(dir.clone())).expect("resolve an explicit home");
        let secret = swoosh::identity::Secret::ephemeral();
        let serve_verb = || match Cli::try_parse_from(["swoosh", "serve"])
            .expect("bare serve parses")
            .command
            .expect("serve is a command")
            .split()
        {
            Verb::Outward(outward) => outward,
            _ => panic!("serve splits to a reaching verb"),
        };

        // Person-zero: no signet file, so this node IS the root and carries the oracle, empty as it is.
        let expose = serve_verb()
            .expose_context(&secret, &home)
            .await
            .expect("expose context resolves")
            .expect("serve carries an expose context");
        let roster = expose
            .roster
            .expect("the signet's own machine may serve a roster");
        assert!(
            roster.bytes().is_empty(),
            "nothing is cut yet, and that is not a reason to refuse the operator's serve"
        );

        // Adopt a foreign signet: this is now a MEMBER device and can never cut a verifiable roster.
        swoosh::config::write_signet(&home, bifrost::NodeId::from_ed25519_secret(&[77u8; 32]))
            .await
            .expect("adopt");
        let expose = serve_verb()
            .expose_context(&secret, &home)
            .await
            .expect("expose context resolves")
            .expect("serve carries an expose context");
        assert!(
            expose.roster.is_none(),
            "a member device must not advertise a roster it cannot sign"
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
    /// parse in its peer slot, uniform across `ping`/`speed`/`status`/`reach`/`send`/`stop --at`/
    /// `service ls --at`/`fetch --via`/`ssh`/`fleet`. `stop` and `service ls` carry the peer on `--at`
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
                &["swoosh", "reach", peer, "web", "--to", "5432"],
                &["swoosh", "send", "afile", peer],
                &["swoosh", "stop", "--at", peer],
                &["swoosh", "service", "ls", "--at", peer],
                &["swoosh", "fetch", "http://example.com/x", "--via", peer],
                &["swoosh", "ssh", peer],
                &["swoosh", "fleet", peer],
            ];
            for argv in cases {
                assert!(
                    Cli::try_parse_from(argv).is_ok(),
                    "{argv:?} should accept the peer form {peer:?}"
                );
            }
        }
    }

    /// At the root, an ssh passthrough token can no longer swallow `--home`. After `--` everything is
    /// ssh's (including a literal `--home`); without the separator an ssh-shaped token is a parse error,
    /// so `swoosh ssh alice -p 2222 --home <dir>` can never silently dial the default home again.
    #[test]
    fn ssh_passthrough_args_do_not_swallow_root_flags() {
        let cli = Cli::try_parse_from([
            "swoosh",
            "--home",
            "/tmp/right",
            "ssh",
            "alice",
            "--",
            "-p",
            "2222",
            "--home",
            "/tmp/is-ssh-arg",
        ])
        .expect("the separated form parses");
        assert_eq!(cli.home, Some(PathBuf::from("/tmp/right")));
        let Some(Command::Ssh(cmd)) = cli.command else {
            panic!("ssh parses to the ssh verb");
        };
        assert_eq!(cmd.args, ["-p", "2222", "--home", "/tmp/is-ssh-arg"]);

        assert!(
            Cli::try_parse_from(["swoosh", "ssh", "alice", "-p", "2222", "--home", "/tmp/x"])
                .is_err(),
            "an ssh-shaped token before `--` must be a parse error, never a silent capture"
        );
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
            Some(Command::Ping(ping::PingCmd {
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
            Some(Command::Ping(ping::PingCmd {
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
            Some(Command::Ping(ping::PingCmd {
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
            Some(Command::Ping(ping::PingCmd {
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
                Some(Command::Serve(serve::ServeCmd {
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

    /// The bind's one mechanism is constructor selection: `--local` picks the persisted-minimal iroh
    /// bind, else the verb's bind role picks between the serving (publishing) and the dialing
    /// (non-publishing) n0 constructors. A pure mapping, so every branch is covered without a socket,
    /// and the composition root's match has an arm per mode with no wildcard.
    #[test]
    fn the_local_flag_and_bind_role_select_the_iroh_constructor() {
        let dialing = || BindRole::Dialing(credential::Credential::Family { present: None });
        assert_eq!(IrohBind::of(false, &BindRole::Serving), IrohBind::Reachable);
        assert_eq!(IrohBind::of(false, &dialing()), IrohBind::Dialing);
        assert_eq!(IrohBind::of(true, &BindRole::Serving), IrohBind::Local);
        assert_eq!(IrohBind::of(true, &dialing()), IrohBind::Local);
    }

    /// F1 (0.9.1): only `serve` writes the home key's address record. A dialing verb on the serving
    /// machine must not touch what other machines resolve, and the table fails on the old switch (every
    /// verb selected the publishing constructor). Asserted through the constructor each role selects,
    /// which is the observable consequence the bind acts on. One parseable argv per reach verb, split to
    /// its [`Verb::Outward`] arm.
    #[test]
    fn only_serve_registers_the_node_record() {
        let key = NodeId::from_ed25519_secret(&[7u8; 32]).to_string();
        let cases: Vec<(Vec<&str>, IrohBind)> = vec![
            (vec!["swoosh", "serve"], IrohBind::Reachable),
            (vec!["swoosh", "ping", &key], IrohBind::Dialing),
            (vec!["swoosh", "speed", &key], IrohBind::Dialing),
            (vec!["swoosh", "status", &key], IrohBind::Dialing),
            (
                vec!["swoosh", "fetch", "https://example.com", "--via", &key],
                IrohBind::Dialing,
            ),
            (
                vec!["swoosh", "reach", &key, "web", "--to", "-"],
                IrohBind::Dialing,
            ),
            (vec!["swoosh", "send", "notes.md", &key], IrohBind::Dialing),
            (vec!["swoosh", "stop", "--at", &key], IrohBind::Dialing),
            (
                vec!["swoosh", "service", "ls", "--at", &key],
                IrohBind::Dialing,
            ),
            (vec!["swoosh", "fleet", &key], IrohBind::Dialing),
        ];

        for (argv, expected) in cases {
            let cli = Cli::try_parse_from(argv.iter().copied())
                .unwrap_or_else(|err| panic!("{argv:?} parses: {err}"));
            let Some(command) = cli.command else {
                panic!("{argv:?} selects a verb");
            };
            let Verb::Outward(outward) = command.split() else {
                panic!("{argv:?} must split to the reach path");
            };
            assert_eq!(
                IrohBind::of(false, &outward.bind_role()),
                expected,
                "{argv:?} must select the {expected:?} constructor"
            );
        }
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
            matches!(cmd.bind_role(), BindRole::Serving),
            "serve still serves, and states no dial credential"
        );
        assert_eq!(
            cmd.identity(),
            swoosh::identity::Identity::Persisted,
            "serve still binds the persisted key"
        );
    }

    /// The one control grammar: BARE `stop` splits to the local (own-node) path, `stop --at <peer>`
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
            Verb::Outward(Outward::Stop(_))
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
            Verb::Outward(Outward::Service(_))
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

    /// Synthetic event metadata for the filter probes: the receive engine's target at INFO, plus a
    /// NON-transfer target at INFO and at ERROR. `Metadata::new` is const, so each probe is a static.
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

    /// The default filter shows errors and nothing below them, for every target: the receive engine's
    /// target gets no raised default, because an arrival is an activity line the serving root renders,
    /// never a log event. An explicit `RUST_LOG` replaces the default.
    #[test]
    fn the_default_log_filter_is_errors_only() {
        use tracing_subscriber::filter::LevelFilter;

        let default = log_filter(None);
        assert!(!filter_enables(&default, &PROBE_TRANSFER_INFO));
        assert!(!filter_enables(&default, &PROBE_OTHER_INFO));
        assert!(filter_enables(&default, &PROBE_OTHER_ERROR));
        assert_eq!(default.max_level_hint(), Some(LevelFilter::ERROR));

        // `RUST_LOG` wins, in both directions.
        let info = log_filter(Some("transfer=info".to_owned()));
        assert!(filter_enables(&info, &PROBE_TRANSFER_INFO));
        let warn = log_filter(Some("warn".to_owned()));
        assert_eq!(warn.max_level_hint(), Some(LevelFilter::WARN));
        assert!(filter_enables(&warn, &PROBE_OTHER_ERROR));
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
            Some(Command::Invite(invite::InviteCmd::Add(_)))
        ));
        assert!(matches!(
            Cli::try_parse_from(["swoosh", "invite", "ls"])
                .expect("invite ls parses")
                .command,
            Some(Command::Invite(invite::InviteCmd::Ls(_)))
        ));
        assert!(matches!(
            Cli::try_parse_from(["swoosh", "invite", "rm", "desk"])
                .expect("invite rm parses")
                .command,
            Some(Command::Invite(invite::InviteCmd::Rm(_)))
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
