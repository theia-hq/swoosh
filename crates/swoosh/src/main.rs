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
//! key and keeps a stable address across runs (and across transports: `--transport iroh|quirk` swaps the
//! backend without changing the key). The outward verbs only dial out, so they mint a throwaway key each
//! run unless you pin a home with `--home`/`SWOOSH_HOME` (the key then lives at `<home>/identity.key`).
//! The full verb arc (send, tunnel, share, fetch, run, cluster, MagicDNS names) is tracked in the README's
//! Roadmap; it ticks as it ships.

use std::path::PathBuf;

use bifrost::{Discovery, Node, Transport};
use clap::{CommandFactory, Parser, Subcommand};
// The verb modules live in the swoosh LIBRARY (`lib.rs`), so an integration test can drive the same pieces
// this binary composes. The binary owns only the CLI surface below (the clap tree and composition root).
use swoosh::commands::adopt::AdoptCmd;
use swoosh::commands::contact::ContactCmd;
use swoosh::commands::fetch::FetchCmd;
use swoosh::commands::fleet::FleetCmd;
use swoosh::commands::forward::ForwardCmd;
use swoosh::commands::grant::GrantCmd;
use swoosh::commands::identity::IdentityCmd;
use swoosh::commands::mint::MintCmd;
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
use swoosh::transport::PeerHint;
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
    /// the node home: key, trust, contacts (the key lives at <home>/identity.key)
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
    /// Be a node: publish named services behind your signet gate (bare = answer reach diagnostics).
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
    /// Show the connection path to a peer: direct vs relayed, remote, and live RTT.
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
    #[command(visible_alias = "id")]
    Identity(IdentityCmd),
    /// Derive a device identity from your signet and emit an authkey for a machine to adopt.
    Mint(MintCmd),
    /// Adopt a minted authkey: become that device identity and trust the signet that minted it.
    Adopt(AdoptCmd),
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
            Self::Mint(cmd) => Verb::Mint(cmd),
            Self::Adopt(cmd) => Verb::Adopt(cmd),
            Self::Ssh(cmd) => Verb::Ssh(cmd),
            Self::Tree(cmd) => Verb::Tree(cmd),
            Self::Grant(cmd) => Verb::Grant(cmd),
            Self::TunnelConnect(cmd) => Verb::Reach(Reach::TunnelConnect(cmd)),
            Self::Forward(cmd) => Verb::Reach(Reach::Forward(cmd)),
            Self::Send(cmd) => Verb::Reach(Reach::Send(cmd)),
            Self::Fleet(cmd) => Verb::Reach(Reach::Fleet(cmd)),
            // `stop --at <peer>` reaches a peer's `control.stop`; a bare `stop` stops YOUR OWN node, which
            // needs the daemon's control socket (not built yet). Split on `--at` here so the bare case reports
            // it WITHOUT composing a transport it would never use, the same local dispatch `ssh`/`grant` take.
            Self::Stop(cmd) => match cmd.at {
                Some(_) => Verb::Reach(Reach::Stop(cmd)),
                None => Verb::Stop(cmd),
            },
            // The `service` group: `ls --at <peer>` reaches a peer's `control.services`; bare `ls` reads your
            // own node (needs the daemon), and `enable`/`disable` are LOCAL file-writes on `<home>/disabled`.
            // Split each here so the local arms never compose a transport they would not use.
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
            Self::Status(cmd) => Verb::Reach(Reach::Status(cmd)),
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
    /// Derives a device identity and records `me/<label>`; needs the key (the signet) and the store, no
    /// transport.
    Mint(MintCmd),
    /// Adopts an authkey: writes the device identity + trusted signet; needs the home, no store or
    /// transport.
    Adopt(AdoptCmd),
    /// Reads the address book to resolve a peer, then execs the system `ssh` over the overlay. A launcher:
    /// it reaches a peer, but binds no transport of its own (tightbeam, run as ssh's `ProxyCommand`, does),
    /// so it dispatches beside the local verbs, off the store, before any transport is composed.
    Ssh(SshCmd),
    /// A bare `swoosh service ls` (no `--at`): reading your OWN node's live menu needs the daemon (not built
    /// yet), so it reports that and needs no transport or store. With `--at` it is a reaching verb instead.
    ServiceLs(ServiceLsCmd),
    /// `swoosh service enable <svc>`: a LOCAL file-write on `<home>/disabled` (remove a name), no transport.
    ServiceEnable(ServiceToggleCmd),
    /// `swoosh service disable <svc>`: a LOCAL file-write on `<home>/disabled` (add a name), no transport.
    ServiceDisable(ServiceToggleCmd),
    /// A bare `swoosh stop` (no `--at`): stopping your OWN node needs the daemon (not built yet), so it
    /// reports that and needs no transport or store. With `--at` it is a reaching verb instead.
    Stop(StopCmd),
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

    /// The reach-family flags this verb carries (`--transport`, `--peer`). Shared by every reaching verb
    /// and no local one, so they are flattened into each reach command rather than made a root global;
    /// the composition root reads them here to pick the backend and seed discovery.
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
    ) -> eyre::Result<(Option<String>, Option<String>)> {
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

/// The real entry point, split from `main` so a failure prints its clean message chain rather than
/// eyre's `Debug` form (see the note in `main`).
async fn run() -> eyre::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
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
        // A bare `swoosh service ls` (no `--at`): reading your own node needs the daemon (not built yet).
        // Report it here, before any transport is composed, the same local dispatch the other transport-free
        // verbs take. With `--at` this verb fell through to the reach path above instead.
        Verb::ServiceLs(cmd) => return cmd.run_local(),
        // A bare `swoosh stop` (no `--at`): stopping your own node needs the daemon (not built yet). Report it
        // here too, before any transport is composed. With `--at` it fell through to the reach path above.
        Verb::Stop(cmd) => return cmd.run_local(),
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
        // Derives a device identity from the signet and records `me/<label>`. Needs the key (to derive)
        // and the store (to record the contact); binds no transport.
        Verb::Mint(cmd) => {
            let store = ContactsStore::open(home.contacts()).await?;
            return cmd.run(store, &home).await;
        }
        // Provisions this machine from an authkey (writes the tightbeam identity + signet). Needs only the
        // home; binds no transport and touches no address book.
        Verb::Adopt(cmd) => return cmd.run(&home).await,
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
        present,
        membership,
        home: &home,
    };
    match transport {
        // iroh self-discovers (n0 pkarr/DNS + relays) AND honors explicit hints: the composed
        // discovery feeds it the `--peer` addresses and any LAN peer heard over mDNS as direct
        // addresses, so a same-network dial goes straight there instead of relaying. With nothing
        // known locally the resolve is empty and iroh self-discovers exactly as before.
        transport::Transport::Iroh => {
            let endpoint = bifrost_iroh::Endpoint::bind_with_secret(secret.into_bytes()).await?;
            let discovery = PeerHint::discovery(&endpoint, peers);
            let node = Node::new(endpoint, discovery);
            run_and_close(reach, &node, ctx).await
        }
        // quirk is direct-only with no internal discovery, so the composed discovery is its only way
        // to learn a peer's address: the `--peer` hints, plus any peer heard over mDNS on the LAN.
        transport::Transport::Quirk => {
            let endpoint = bifrost_quirk::Endpoint::bind_with_secret(secret.into_bytes()).await?;
            let discovery = PeerHint::discovery(&endpoint, peers);
            let node = Node::new(endpoint, discovery);
            run_and_close(reach, &node, ctx).await
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
        tightbeam::tunnel::mint_signet_link(
            &work,
            &"ssh".parse().expect("valid service"),
            fleet,
            core::time::Duration::from_secs(3600),
        )
        .expect("mint a sheer: link")
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
}
