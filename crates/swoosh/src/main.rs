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
// The verb modules live in the swoosh LIBRARY (`lib.rs`), so an integration test can drive the same pieces
// this binary composes. The binary owns only the CLI surface below (the clap tree and composition root).
use swoosh::commands::adopt::AdoptCmd;
use swoosh::commands::contact::ContactCmd;
use swoosh::commands::fetch::FetchCmd;
use swoosh::commands::forward::ForwardCmd;
use swoosh::commands::grant::GrantCmd;
use swoosh::commands::identity::IdentityCmd;
use swoosh::commands::mint::MintCmd;
use swoosh::commands::ping::PingCmd;
use swoosh::commands::serve::ServeCmd;
use swoosh::commands::speed::SpeedCmd;
use swoosh::commands::ssh::SshCmd;
use swoosh::commands::status::StatusCmd;
use swoosh::commands::tree::TreeCmd;
use swoosh::commands::tunnel_connect::TunnelConnectCmd;
use swoosh::contacts::{Contacts, ContactsStore};
use swoosh::identity::Identity;
use swoosh::transport::Peer;
use swoosh::{config, contacts, identity, transport};

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
    /// Be a node: publish named services behind your signet gate (bare = answer reach diagnostics).
    Serve(ServeCmd),
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
    /// Mint, narrow, or revoke a `sheer:` capability link.
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
    /// Mints, narrows, or revokes a `sheer:` capability link. `share` signs with the persisted key;
    /// `attenuate` and `revoke` are wholly offline. No leaf binds a transport or reads the address book.
    Grant(GrantCmd),
    /// Reaches a peer; binds a transport.
    Reach(Reach),
}

impl Reach {
    /// The identity this verb binds under. `serve` must be reachable at a stable address, so it
    /// persists; the reach-outward verbs address a peer and are never dialed back, so they are
    /// ephemeral by default. An explicit `--key` overrides either (see [`identity::resolve`]).
    fn identity(&self) -> Identity {
        match self {
            // `serve` roots its services and any share-link at a stable key AND must be reachable at one
            // address, so it persists; `tunnel-connect` must dial under swoosh's OWN key so the family gate
            // proves the identity the membership badge was minted for. Both persist.
            Self::Serve(_) | Self::TunnelConnect(_) => Identity::Persisted,
            // `forward` is a dial-only client (it presents a link, not swoosh's identity), so it is
            // ephemeral like the other reach-outward verbs.
            Self::Forward(_) => Identity::Ephemeral,
            // The diagnostic verbs reach a peer's GATED `ping`/`speed` service presenting a self-signed badge, so
            // they must dial under the persisted identity WHEN one exists (the badge roots at the dialing
            // key, so an ephemeral key's self-badge would be refused by the peer's family gate). A fresh
            // install with no persisted key still dials out ephemerally. `--present` carries a link for a
            // non-signet member either way.
            Self::Ping(_) | Self::Speed(_) | Self::Status(_) => Identity::PersistedIfPresent,
            Self::Fetch(_) => Identity::Ephemeral,
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
            // `serve` drives the gated exposer, so it needs the `ExposeContext` (host seed, signet,
            // denylist) resolved in the root before the transport consumed the secret.
            Self::Serve(cmd) => {
                let ExposeContext {
                    host_seed,
                    signet,
                    denylist,
                } = expose.ok_or_else(|| {
                    eyre::eyre!("internal: serve reached without its expose context")
                })?;
                cmd.run(node, host_seed, signet, denylist).await
            }
            // The diagnostic verbs reach the peer's GATED `ping`/`speed` service, so they present the self-signed
            // membership badge (minted below in `self_badge`) the same way `tunnel-connect` does.
            Self::Ping(cmd) => cmd.run(node, contacts, transport, self_badge).await,
            Self::Speed(cmd) => cmd.run(node, contacts, transport, self_badge).await,
            Self::Status(cmd) => cmd.run(node, contacts, transport, self_badge).await,
            Self::Fetch(cmd) => cmd.run(node, contacts, transport).await,
            Self::Forward(cmd) => cmd.run(node).await,
            // The peer is already a resolved raw key, so no address book or transport label is needed; the
            // `self_badge` (this identity's self-signed membership badge) is the signet-holder's proof to
            // present, resolved against any stored badge inside the command.
            Self::TunnelConnect(cmd) => cmd.run(node, self_badge).await,
        }
    }

    /// The membership badge to present when dialing, if this verb dials a family-gated node.
    /// `tunnel-connect` (the `swoosh ssh` bridge) and the diagnostic verbs (`ping`/`speed`/`status`, which
    /// reach the peer's gated `ping`/`speed` service) present one. Computed here, in the composition root, because
    /// it needs the resolved secret before the transport consumes it. Every other reach verb presents
    /// nothing, so returns `None`.
    ///
    /// Present the STORED signet-signed badge if one exists (an adopted device carries the badge the signet
    /// minted FOR it: rooted at the signet, bound to this device -- the only credential a signet-rooted gate
    /// admits). Else self-sign (`member_badge`): the fallback for the signet holder itself (person-zero has
    /// no stored badge -- it IS the root -- and its self-sign roots at the signet, so it admits). A fresh
    /// install with neither badge nor signet key self-signs an ephemeral badge that is correctly refused.
    async fn self_badge(
        &self,
        secret: &identity::Secret,
        key: Option<&std::path::Path>,
    ) -> eyre::Result<Option<String>> {
        match self {
            // `tunnel-connect` (the `swoosh ssh` bridge) and the diagnostic verbs all reach a family-gated
            // service. An adopted DEVICE presents its stored signet-signed badge; the signet holder (no
            // stored badge) self-signs, which roots at the signet and admits.
            Self::TunnelConnect(_) | Self::Ping(_) | Self::Speed(_) | Self::Status(_) => {
                match config::load_badge(key).await? {
                    Some(badge) => Ok(Some(badge)),
                    None => Ok(Some(secret.member_badge()?)),
                }
            }
            _ => Ok(None),
        }
    }

    /// The exposer context `serve` needs, resolved before the secret is consumed by the transport bind:
    /// swoosh's ssh host seed (derived from the secret), the signet its default gate trusts,
    /// and the revocation denylist the gate honors. All read from swoosh's OWN store, dir-derived from
    /// `--key` like the contacts file, so a swoosh node gates on the signet `swoosh adopt` set under the same
    /// `--key`. Every other verb returns `None`. Async because the signet and denylist are read from disk.
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
        key: Option<&std::path::Path>,
    ) -> eyre::Result<Option<ExposeContext>> {
        match self {
            // `serve` drives the gated exposer, so it resolves the exposer context; every other verb
            // returns `None`.
            Self::Serve(_) => Ok(Some(ExposeContext {
                host_seed: secret.ssh_host_seed(),
                signet: Some(
                    config::load_signet(key)
                        .await?
                        .unwrap_or_else(|| secret.node_id()),
                ),
                denylist: nauthy::Denylist::load(config::revoked_path(key)?).await?,
            })),
            _ => Ok(None),
        }
    }
}

/// What `serve` needs beyond the bound node: swoosh's ssh host seed, the trusted signet, and the
/// revocation denylist the gate honors. All are resolved in the composition root (the host seed needs the
/// secret before the transport consumes it), then handed to the serve arm.
struct ExposeContext {
    host_seed: [u8; 32],
    signet: Option<bifrost::NodeId>,
    denylist: nauthy::Denylist,
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
        // The `grant` group: `share` signs a link with the persisted key; `attenuate`/`revoke` are wholly
        // offline. No leaf binds a transport or reads the address book, so the group dispatches here beside
        // the local verbs rather than falling through to the reach path.
        Verb::Grant(cmd) => {
            return match cmd {
                GrantCmd::Issue(cmd) => cmd.run(cli.key.as_deref()).await,
                GrantCmd::Narrow(cmd) => cmd.run(),
                GrantCmd::Revoke(cmd) => cmd.run(cli.key.as_deref()).await,
            };
        }
        // A launcher: read the store to resolve the peer, then hand off to the system `ssh` (which runs
        // tightbeam as its `ProxyCommand`). swoosh binds no transport here; on unix `run` execs and does
        // not return on success.
        Verb::Ssh(cmd) => {
            let store = ContactsStore::open(contacts_path(cli.key.as_deref())?).await?;
            return cmd.run(store.contacts(), cli.key.as_deref());
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
    // Resolve the membership badge to present BEFORE the secret is consumed by the transport bind: an
    // adopted device presents its STORED signet-signed badge (bound to this key, which the dial then binds
    // under, so the far gate's device-binding matches); the signet holder self-signs one against the same
    // key for the same reason. The exposer context (`serve`) is resolved before the bind too: its ssh
    // host seed derives from the secret before the bind consumes it.
    let self_badge = reach.self_badge(&secret, cli.key.as_deref()).await?;
    let expose = reach.expose_context(&secret, cli.key.as_deref()).await?;
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
        let key = dir.join("identity.key");

        // An in-memory secret standing in for the persisted identity; the dir it points at has no signet.
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
            .expose_context(&secret, Some(&key))
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
}
