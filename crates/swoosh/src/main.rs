//! swoosh: one command, one identity, every p2p operation as a verb.
//!
//! `swoosh serve` makes this node answer reach diagnostics; `swoosh ping <key>` measures the round trip
//! to a peer by their public key; `swoosh speed <key>` measures throughput to them; `swoosh status
//! <key>` shows the connection path (direct vs relayed) to a peer. Identity is chosen by intent: `serve`
//! must be reachable, so it binds a persisted key and keeps one stable address across runs (and across
//! transports: `--transport iroh|quirk` swaps the backend underneath without changing that address). The
//! reach-outward verbs need no lasting identity, so they mint a fresh ephemeral key each run unless you
//! pin one with `--key`/`SWOOSH_KEY`. iris and tightbeam verbs (`send`/`recv`/`tunnel`) land next; see
//! the README.

use std::path::PathBuf;

use bifrost::{Discovery, Node, Transport};
use clap::{Parser, Subcommand};

mod commands;
mod contacts;
mod identity;
mod reach;
mod transport;

use commands::contact::ContactCmd;
use commands::ping::PingCmd;
use commands::serve::ServeCmd;
use commands::speed::SpeedCmd;
use commands::status::StatusCmd;
use contacts::{Contacts, ContactsStore};
use identity::Identity;
use transport::Peer;

/// The unified front door to the theia overlay: reach, name, and run code at a public key.
#[derive(Debug, Parser)]
#[command(name = "swoosh", version, about)]
struct Cli {
    /// Which transport to bind under the identity. iroh self-discovers across the internet; quirk is
    /// direct-only. Both find peers on the same LAN over mDNS and honor `--peer` hints. The NodeId is
    /// identical whichever is chosen. Global, so it may sit before or after the verb.
    #[arg(long, value_enum, default_value_t, global = true)]
    transport: transport::Transport,
    /// A direct address hint for a peer, `<key>=<socketaddr>`, repeatable. Honored by both transports.
    /// Rarely needed on a LAN, where peers find each other automatically over mDNS; feed back what a
    /// peer's `swoosh serve` prints to reach it across networks. Global, so it may sit after the verb
    /// next to the peer key it hints.
    #[arg(long, global = true)]
    peer: Vec<Peer>,
    /// Pin this run to a persisted identity at the given file, creating it if absent. Without it,
    /// `serve` uses the default key file and the reach-outward verbs mint a fresh ephemeral key. Global,
    /// so it may sit before or after the verb. The id is distinct from a verb's positional `key` (a peer
    /// `NodeId`); the two never collide.
    #[arg(long = "key", id = "identity-key", env = "SWOOSH_KEY", global = true)]
    key: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Answer reach diagnostics from peers. Prints this node's address, then stays online.
    Serve(ServeCmd),
    /// Measure the round-trip time to a peer, addressed by a petname or their public key.
    Ping(PingCmd),
    /// Measure throughput to a peer: iperf, but over the overlay.
    Speed(SpeedCmd),
    /// Show the connection path to a peer: direct vs relayed, remote, and live RTT.
    Status(StatusCmd),
    /// Manage local petnames: save, list, and remove peer aliases.
    #[command(subcommand)]
    Contact(ContactCmd),
}

/// A verb that reaches a peer: it binds a transport and dials. Split from the local `contact` group,
/// which touches only the address book and never composes a transport.
enum Reach {
    Serve(ServeCmd),
    Ping(PingCmd),
    Speed(SpeedCmd),
    Status(StatusCmd),
}

impl Command {
    /// Split the parsed verb into the local `contact` group (no transport) or a reaching verb (binds
    /// one). The two paths diverge before any transport is composed, so `contact add` never spins up an
    /// endpoint it does not need.
    fn split(self) -> Verb {
        match self {
            Self::Contact(cmd) => Verb::Contact(cmd),
            Self::Serve(cmd) => Verb::Reach(Reach::Serve(cmd)),
            Self::Ping(cmd) => Verb::Reach(Reach::Ping(cmd)),
            Self::Speed(cmd) => Verb::Reach(Reach::Speed(cmd)),
            Self::Status(cmd) => Verb::Reach(Reach::Status(cmd)),
        }
    }
}

/// The two kinds of verb, once split: purely local, or reaching outward over a transport.
enum Verb {
    /// Edits the address book; needs no transport.
    Contact(ContactCmd),
    /// Reaches a peer; binds a transport.
    Reach(Reach),
}

impl Reach {
    /// The identity this verb binds under. `serve` must be reachable at a stable address, so it
    /// persists; the reach-outward verbs address a peer and are never dialed back, so they are
    /// ephemeral by default. An explicit `--key` overrides either (see [`identity::resolve`]).
    fn identity(&self) -> Identity {
        match self {
            Self::Serve(_) => Identity::Persisted,
            Self::Ping(_) | Self::Speed(_) | Self::Status(_) => Identity::Ephemeral,
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
    ) -> eyre::Result<()> {
        match self {
            Self::Serve(cmd) => cmd.run(node).await,
            Self::Ping(cmd) => cmd.run(node, contacts, transport).await,
            Self::Speed(cmd) => cmd.run(node, contacts, transport).await,
            Self::Status(cmd) => cmd.run(node, contacts, transport).await,
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

/// The real entry point, split from `main` so a failure prints its clean message chain rather than
/// eyre's `Debug` form (see the note in `main`).
async fn run() -> eyre::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    // The address book lives beside the identity, honoring `--key`'s dir when it points elsewhere, else
    // the default config dir. Open it once, up front: the `contact` group edits it, the reach verbs read
    // it to resolve a petname.
    let store = ContactsStore::open(contacts_path(cli.key.as_deref())?).await?;

    // A `contact` verb is purely local: it edits the address book and dials nobody, so it runs here
    // before any transport is composed. Everything else reaches a peer, so it falls through to bind one.
    let reach = match cli.command.split() {
        Verb::Contact(cmd) => return cmd.run(store).await,
        Verb::Reach(reach) => reach,
    };

    // The verb decides its identity: `serve` persists so it is reachable at one address, the reach-
    // outward verbs mint a fresh ephemeral key, and an explicit `--key` pins either. Resolve it before
    // binding, since the secret is what the transport is bound under.
    let secret = identity::resolve(reach.identity(), cli.key.as_deref()).await?;
    let contacts = Contacts::clone(store.contacts());

    // The one and only place a concrete transport is named. Everything downstream speaks `bifrost`. The
    // same secret yields the same NodeId whether bound under iroh or quirk, which is what makes the
    // transport swap a swap and not a new node.
    let transport = cli.transport;
    match transport {
        // iroh self-discovers (n0 pkarr/DNS + relays) AND honors explicit hints: the composed
        // discovery feeds it the `--peer` addresses and any LAN peer heard over mDNS as direct
        // addresses, so a same-network dial goes straight there instead of relaying. With nothing
        // known locally the resolve is empty and iroh self-discovers exactly as before.
        transport::Transport::Iroh => {
            let endpoint = bifrost_iroh::Endpoint::bind_with_secret(secret.into_bytes()).await?;
            let discovery = Peer::discovery(&endpoint, cli.peer);
            let node = Node::new(endpoint, discovery);
            reach.run(&node, &contacts, transport).await
        }
        // quirk is direct-only with no internal discovery, so the composed discovery is its only way
        // to learn a peer's address: the `--peer` hints, plus any peer heard over mDNS on the LAN.
        transport::Transport::Quirk => {
            let endpoint = bifrost_quirk::Endpoint::bind_with_secret(secret.into_bytes()).await?;
            let discovery = Peer::discovery(&endpoint, cli.peer);
            let node = Node::new(endpoint, discovery);
            reach.run(&node, &contacts, transport).await
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
