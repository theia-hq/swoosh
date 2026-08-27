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

use bifrost::{Discovery, NoDiscovery, Node, Transport};
use clap::{Parser, Subcommand};

mod commands;
mod identity;
mod transport;

use commands::ping::PingCmd;
use commands::serve::ServeCmd;
use commands::speed::SpeedCmd;
use commands::status::StatusCmd;
use identity::Identity;
use transport::Peer;

/// The unified front door to the theia overlay: reach, name, and run code at a public key.
#[derive(Debug, Parser)]
#[command(name = "swoosh", version, about)]
struct Cli {
    /// Which transport to bind under the identity. iroh self-discovers; quirk is direct-only and pairs
    /// with `--peer` hints. The NodeId is identical whichever is chosen. Global, so it may sit before or
    /// after the verb.
    #[arg(long, value_enum, default_value_t, global = true)]
    transport: transport::Transport,
    /// A direct address hint for quirk, `<key>=<socketaddr>`, repeatable. Ignored by iroh, which
    /// self-discovers. Feed back what a peer's `swoosh serve` prints. Global, so it may sit after the
    /// verb next to the peer key it hints.
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
    /// Measure the round-trip time to a peer, addressed by their public key.
    Ping(PingCmd),
    /// Measure throughput to a peer: iperf, but over the overlay.
    Speed(SpeedCmd),
    /// Show the connection path to a peer: direct vs relayed, remote, and live RTT.
    Status(StatusCmd),
}

impl Command {
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
    /// `transport` label is passed as a plain value for the one verb that reports which backend carried
    /// the session (`status`), so no verb has to name a concrete backend.
    async fn run<T: Transport, D: Discovery>(
        self,
        node: &Node<T, D>,
        transport: transport::Transport,
    ) -> eyre::Result<()> {
        match self {
            Self::Serve(cmd) => cmd.run(node).await,
            Self::Ping(cmd) => cmd.run(node).await,
            Self::Speed(cmd) => cmd.run(node).await,
            Self::Status(cmd) => cmd.run(node, transport).await,
        }
    }
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    // The verb decides its identity: `serve` persists so it is reachable at one address, the reach-
    // outward verbs mint a fresh ephemeral key, and an explicit `--key` pins either. Resolve it before
    // binding, since the secret is what the transport is bound under.
    let secret = identity::resolve(cli.command.identity(), cli.key.as_deref()).await?;

    // The one and only place a concrete transport is named. Everything downstream speaks `bifrost`. The
    // same secret yields the same NodeId whether bound under iroh or quirk, which is what makes the
    // transport swap a swap and not a new node.
    let transport = cli.transport;
    match transport {
        // iroh self-discovers (n0 pkarr/DNS + relays), so it composes with NoDiscovery and ignores
        // `--peer`. Unchanged from the iroh-only skeleton.
        transport::Transport::Iroh => {
            let node = Node::new(
                bifrost_iroh::Endpoint::bind_with_secret(secret.into_bytes()).await?,
                NoDiscovery,
            );
            cli.command.run(&node, transport).await
        }
        // quirk is direct-only with no internal discovery, so it composes with a StaticDiscovery
        // seeded from the `--peer` hints. A client dials a peer by feeding back the `<key>=<addr>`
        // that peer's `serve` prints.
        transport::Transport::Quirk => {
            let node = Node::new(
                bifrost_quirk::Endpoint::bind_with_secret(secret.into_bytes()).await?,
                Peer::discovery(cli.peer),
            );
            cli.command.run(&node, transport).await
        }
    }
}
