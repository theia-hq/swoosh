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
//! run unless you pin one with `--key`/`SWOOSH_KEY`. The full verb arc (send/beam, tunnel, share, fetch,
//! run, cluster, MagicDNS names) is tracked in the README's Roadmap; it ticks as it ships.

use std::path::PathBuf;

use bifrost::{Discovery, Node, Transport};
use clap::{CommandFactory, Parser, Subcommand};

mod authkey;
mod commands;
mod contacts;
mod identity;
mod reach;
mod transport;

use commands::adopt::AdoptCmd;
use commands::attenuate::AttenuateCmd;
use commands::contact::ContactCmd;
use commands::fetch::FetchCmd;
use commands::identity::IdentityCmd;
use commands::mint::MintCmd;
use commands::ping::PingCmd;
use commands::revoke::RevokeCmd;
use commands::serve::ServeCmd;
use commands::share::ShareCmd;
use commands::speed::SpeedCmd;
use commands::ssh::SshCmd;
use commands::status::StatusCmd;
use commands::tree::TreeCmd;
use commands::tunnel::TunnelCmd;
use commands::tunnel_connect::TunnelConnectCmd;
use contacts::{Contacts, ContactsStore};
use identity::Identity;
use transport::Peer;

#[derive(Debug, Parser)]
#[command(
    name = "swoosh",
    version,
    about = "Work with a machine addressed by its public key: reach it, measure it, and more.",
    // A bare `swoosh` is a mistake, not a default action: print the full help and exit non-zero. This
    // must hold even with `SWOOSH_KEY` set, but an env-backed global `--key` counts as an arg to clap,
    // so `arg_required_else_help` would fall to a terse "subcommand required" line there instead of the
    // help. So the subcommand is `Option` and the no-verb case is handled in `run`, one behavior whether
    // or not the env var is set.
    arg_required_else_help = true
)]
struct Cli {
    /// Pin a persisted identity dir [env: SWOOSH_KEY]
    #[arg(long = "key", id = "identity-key", env = "SWOOSH_KEY", global = true)]
    key: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Be online: answer reach diagnostics; prints this node's address.
    Serve(ServeCmd),
    /// Measure the round-trip time to a peer, addressed by a petname or their public key.
    Ping(PingCmd),
    /// Measure throughput to a peer: iperf, but over the overlay.
    Speed(SpeedCmd),
    /// Show the connection path to a peer: direct vs relayed, remote, and live RTT.
    Status(StatusCmd),
    /// Mint a local URL that fetches an origin through a node you name.
    Fetch(FetchCmd),
    /// Expose a local service to peers, or bind a peer's exposed service to a local port.
    #[command(subcommand)]
    Tunnel(TunnelCmd),
    /// Mint a `sheer:` capability link granting one service, expiring, attenuable, delegable.
    Share(ShareCmd),
    /// Narrow an existing `sheer:` link offline before handing it on.
    Attenuate(AttenuateCmd),
    /// Revoke a `sheer:` link so this node refuses it at once, without waiting for expiry.
    Revoke(RevokeCmd),
    /// Manage local petnames: save, list, and remove peer aliases.
    #[command(subcommand)]
    Contact(ContactCmd),
    /// Print this node's identity (its NodeId), minting a key if there is none.
    Identity(IdentityCmd),
    /// Derive a device identity from your signet and emit an authkey for a machine to adopt.
    Mint(MintCmd),
    /// Adopt a minted authkey: become that device identity and trust the signet that minted it.
    Adopt(AdoptCmd),
    /// Reach a peer's sshd over the overlay; runs the system ssh.
    Ssh(SshCmd),
    /// Print this command tree (spec vs binary).
    Tree(TreeCmd),
    /// The in-process ProxyCommand behind `swoosh ssh`: self-invoked via `current_exe()`, never typed.
    /// Hidden from help and `tree` — it is plumbing, not a user verb (see `commands::tunnel_connect`).
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
    /// The public `swoosh tunnel` group: `expose` (serve a local service) or `connect` (bind a remote
    /// service to a local port). Both bind a transport, so the group rides the reach path; the `expose`
    /// arm additionally reads the signet and swoosh's ssh host seed, resolved in the root like `self_badge`.
    Tunnel(TunnelCmd),
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
            Self::Share(cmd) => Verb::Share(cmd),
            Self::Attenuate(cmd) => Verb::Attenuate(cmd),
            Self::Revoke(cmd) => Verb::Revoke(cmd),
            Self::TunnelConnect(cmd) => Verb::Reach(Reach::TunnelConnect(cmd)),
            Self::Tunnel(cmd) => Verb::Reach(Reach::Tunnel(cmd)),
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
    /// Prints this node's identity; needs no transport and no store, only the key path.
    Identity(IdentityCmd),
    /// Derives a device identity and records `me/<label>`; needs the key (the signet) and the store, no
    /// transport.
    Mint(MintCmd),
    /// Adopts an authkey: writes the device identity + trusted signet; needs the key path, no store or
    /// transport.
    Adopt(AdoptCmd),
    /// Reads the address book to resolve a peer, then execs the system `ssh` over the overlay. A launcher:
    /// it reaches a peer, but binds no transport of its own (tightbeam, run as ssh's `ProxyCommand`, does),
    /// so it dispatches beside the local verbs, off the store, before any transport is composed.
    Ssh(SshCmd),
    /// Prints the command tree; needs no transport and no store.
    Tree(TreeCmd),
    /// Mints a `sheer:` capability link; signs with the persisted key, binds no transport and no store.
    Share(ShareCmd),
    /// Narrows a `sheer:` link offline; needs no identity, transport, or store.
    Attenuate(AttenuateCmd),
    /// Revokes a `sheer:` link into the local denylist; needs no identity, transport, or store.
    Revoke(RevokeCmd),
    /// Reaches a peer; binds a transport.
    Reach(Reach),
}

impl Reach {
    /// The identity this verb binds under. `serve` must be reachable at a stable address, so it
    /// persists; the reach-outward verbs address a peer and are never dialed back, so they are
    /// ephemeral by default. An explicit `--key` overrides either (see [`identity::resolve`]).
    fn identity(&self) -> Identity {
        match self {
            // `serve` must be reachable at a stable address; `tunnel-connect` must dial under swoosh's OWN
            // key so the family gate proves the identity the membership badge was minted for. Both persist.
            Self::Serve(_) | Self::TunnelConnect(_) => Identity::Persisted,
            // `tunnel expose` roots its services and any share-link at a stable key, so it persists;
            // `tunnel connect` is a dial-only client (it presents a link, not swoosh's identity), so it is
            // ephemeral like the other reach-outward verbs.
            Self::Tunnel(cmd) => match cmd {
                TunnelCmd::Expose(_) => Identity::Persisted,
                TunnelCmd::Connect(_) => Identity::Ephemeral,
            },
            Self::Ping(_) | Self::Speed(_) | Self::Status(_) | Self::Fetch(_) => {
                Identity::Ephemeral
            }
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
            Self::Tunnel(cmd) => match cmd {
                TunnelCmd::Expose(cmd) => &cmd.reach,
                TunnelCmd::Connect(cmd) => &cmd.reach,
            },
            Self::TunnelConnect(cmd) => &cmd.reach,
        }
    }

    /// Run the selected verb against the composed node. Every verb is generic over `Node<T, D>`, so
    /// this dispatch is transport-blind: the concrete transport was chosen once, at the seam below. The
    /// reach-outward verbs take `contacts` to resolve a petname in their peer slot; the `transport`
    /// label is passed as a plain value so a verb can report which backend carried the session
    /// (`status`) and so a failed dial can name the fix that backend needs, without any verb naming a
    /// concrete backend.
    async fn run<T: Transport, D: Discovery>(
        self,
        node: &Node<T, D>,
        contacts: &Contacts,
        transport: transport::Transport,
        self_badge: Option<String>,
        expose: Option<ExposeContext>,
    ) -> eyre::Result<()>
    where
        <T::Session as bifrost::Session>::Write: Send + 'static,
        <T::Session as bifrost::Session>::Read: Send + 'static,
    {
        match self {
            Self::Serve(cmd) => cmd.run(node).await,
            Self::Ping(cmd) => cmd.run(node, contacts, transport).await,
            Self::Speed(cmd) => cmd.run(node, contacts, transport).await,
            Self::Status(cmd) => cmd.run(node, contacts, transport).await,
            Self::Fetch(cmd) => cmd.run(node, contacts, transport).await,
            Self::Tunnel(cmd) => match cmd {
                // `expose` reads the signet its default gate trusts and swoosh's own ssh host seed, both
                // resolved in the root before the secret was consumed by the transport bind (see
                // `ExposeContext`). It is only ever `Some` on this arm.
                TunnelCmd::Expose(cmd) => {
                    let ExposeContext { host_seed, signet } = expose.ok_or_else(|| {
                        eyre::eyre!("internal: tunnel expose reached without its context")
                    })?;
                    cmd.run(node, host_seed, signet).await
                }
                TunnelCmd::Connect(cmd) => cmd.run(node).await,
            },
            // The peer is already a resolved raw key, so no address book or transport label is needed; the
            // `self_badge` (this identity's self-signed membership badge) is the signet-holder's proof to
            // present, resolved against any stored badge inside the command.
            Self::TunnelConnect(cmd) => cmd.run(node, self_badge).await,
        }
    }

    /// The self-signed membership badge to present when dialing, if this verb dials a family-gated node.
    /// Only `tunnel-connect` (the `swoosh ssh` bridge) presents one: the signet holder self-signs a badge
    /// bound to its own key so it proves membership without carrying a stored one. Computed here, in the
    /// composition root, because it needs the resolved secret before the transport consumes it. Every other
    /// reach verb presents nothing, so returns `None`.
    fn self_badge(&self, secret: &identity::Secret) -> eyre::Result<Option<String>> {
        match self {
            Self::TunnelConnect(_) => Ok(Some(secret.member_badge()?)),
            _ => Ok(None),
        }
    }

    /// The exposer context `tunnel expose` needs, resolved before the secret is consumed by the transport
    /// bind: swoosh's ssh host seed (derived from the secret) and the signet its default gate trusts (read
    /// from tightbeam's config, so a swoosh node gates on the same signet `swoosh adopt` set). Every other
    /// verb returns `None`. Async because the signet is read from disk.
    async fn expose_context(
        &self,
        secret: &identity::Secret,
    ) -> eyre::Result<Option<ExposeContext>> {
        match self {
            Self::Tunnel(TunnelCmd::Expose(_)) => Ok(Some(ExposeContext {
                host_seed: secret.ssh_host_seed(),
                signet: tightbeam::config::load_signet().await?,
            })),
            _ => Ok(None),
        }
    }
}

/// What `tunnel expose` needs beyond the bound node: swoosh's ssh host seed and the trusted signet. Both
/// are resolved in the composition root (the host seed needs the secret before the transport consumes it),
/// then handed to the exposer arm.
struct ExposeContext {
    host_seed: [u8; 32],
    signet: Option<bifrost::NodeId>,
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

/// The real entry point, split from `main` so a failure prints its clean message chain rather than
/// eyre's `Debug` form (see the note in `main`).
async fn run() -> eyre::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    // No verb given (a bare `swoosh`, even with `SWOOSH_KEY` set): print the full help and exit non-zero,
    // the same way clap's own `arg_required_else_help` does (full help, non-zero exit, no `Error:` line).
    // See the note on `Cli` for why this is handled here rather than by that attribute alone.
    let Some(command) = cli.command else {
        let mut help = Cli::command();
        help.print_help()?;
        std::process::exit(2);
    };

    // Local verbs run here, before any transport is composed and (for `tree`) before the store is even
    // opened: `tree` is pure introspection over clap's own model, and `contact` only edits the address
    // book. A reaching verb falls through to bind a transport below.
    let reach = match command.split() {
        Verb::Tree(cmd) => return cmd.run(&Cli::command()),
        Verb::Contact(cmd) => {
            let store = ContactsStore::open(contacts_path(cli.key.as_deref())?).await?;
            return cmd.run(store).await;
        }
        // Prints this node's NodeId (minting a key if absent). Needs only the key path, not the store or
        // a transport, so it dispatches here beside the other local verbs.
        Verb::Identity(cmd) => return cmd.run(cli.key.as_deref()).await,
        // Derives a device identity from the signet and records `me/<label>`. Needs the key (to derive)
        // and the store (to record the contact); binds no transport.
        Verb::Mint(cmd) => {
            let store = ContactsStore::open(contacts_path(cli.key.as_deref())?).await?;
            return cmd.run(store, cli.key.as_deref()).await;
        }
        // Provisions this machine from an authkey (writes the tightbeam identity + signet). Needs only the
        // key path; binds no transport and touches no address book.
        Verb::Adopt(cmd) => return cmd.run(cli.key.as_deref()).await,
        // Cap verbs: `share` signs a link with the persisted key; `attenuate`/`revoke` are wholly offline.
        // None binds a transport or reads the address book, so they dispatch here beside the local verbs.
        Verb::Share(cmd) => return cmd.run(cli.key.as_deref()).await,
        Verb::Attenuate(cmd) => return cmd.run(),
        Verb::Revoke(cmd) => return cmd.run().await,
        // A launcher: read the store to resolve the peer, then hand off to the system `ssh` (which runs
        // tightbeam as its `ProxyCommand`). swoosh binds no transport here; on unix `run` execs and does
        // not return on success.
        Verb::Ssh(cmd) => {
            let store = ContactsStore::open(contacts_path(cli.key.as_deref())?).await?;
            return cmd.run(store.contacts());
        }
        Verb::Reach(reach) => reach,
    };

    // The address book lives beside the identity, honoring `--key`'s dir when it points elsewhere, else
    // the default config dir. A reach verb reads it to resolve a petname in its peer slot.
    let store = ContactsStore::open(contacts_path(cli.key.as_deref())?).await?;

    // The verb decides its identity: `serve` persists so it is reachable at one address, the reach-
    // outward verbs mint a fresh ephemeral key, and an explicit `--key` pins either. Resolve it before
    // binding, since the secret is what the transport is bound under.
    let secret = identity::resolve(reach.identity(), cli.key.as_deref()).await?;
    let contacts = Contacts::clone(store.contacts());

    // The one and only place a concrete transport is named. Everything downstream speaks `bifrost`. The
    // same secret yields the same NodeId whether bound under iroh or quirk, which is what makes the
    // transport swap a swap and not a new node. The reach-family flags travel on the verb itself now, so
    // the backend and the dial hints are read off the chosen reaching verb, not a root global.
    let transport = reach.args().transport;
    let peers = reach.args().peer.clone();
    // Sign the membership badge (only `tunnel-connect` produces one) BEFORE the secret is consumed by the
    // transport bind: it self-signs against the same key the dial then binds under, so the badge's device
    // binding matches the identity the far gate proves. The exposer context (`tunnel expose`) is resolved
    // for the same reason: its ssh host seed derives from the secret before the bind consumes it.
    let self_badge = reach.self_badge(&secret)?;
    let expose = reach.expose_context(&secret).await?;
    match transport {
        // iroh self-discovers (n0 pkarr/DNS + relays) AND honors explicit hints: the composed
        // discovery feeds it the `--peer` addresses and any LAN peer heard over mDNS as direct
        // addresses, so a same-network dial goes straight there instead of relaying. With nothing
        // known locally the resolve is empty and iroh self-discovers exactly as before.
        transport::Transport::Iroh => {
            let endpoint = bifrost_iroh::Endpoint::bind_with_secret(secret.into_bytes()).await?;
            let discovery = Peer::discovery(&endpoint, peers);
            let node = Node::new(endpoint, discovery);
            reach
                .run(&node, &contacts, transport, self_badge, expose)
                .await
        }
        // quirk is direct-only with no internal discovery, so the composed discovery is its only way
        // to learn a peer's address: the `--peer` hints, plus any peer heard over mDNS on the LAN.
        transport::Transport::Quirk => {
            let endpoint = bifrost_quirk::Endpoint::bind_with_secret(secret.into_bytes()).await?;
            let discovery = Peer::discovery(&endpoint, peers);
            let node = Node::new(endpoint, discovery);
            reach
                .run(&node, &contacts, transport, self_badge, expose)
                .await
        }
    }
}

/// The contacts file to open: beside an explicit `--key`, else the default config location.
///
/// A pinned `--key` moves the whole identity dir, so the address book follows it and stays one identity,
/// one address book. Without it the default `~/.config/swoosh/contacts.toml` applies.
fn contacts_path(key: Option<&std::path::Path>) -> eyre::Result<PathBuf> {
    match key.and_then(std::path::Path::parent) {
        Some(dir) => Ok(dir.join("contacts.toml")),
        None => Ok(contacts::default_path()?),
    }
}
