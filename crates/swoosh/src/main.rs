//! swoosh: one command, one identity, every p2p operation as a verb.
//!
//! `swoosh serve` makes this node answer reach diagnostics; `swoosh ping <key>` measures the round trip
//! to a peer by their public key; `swoosh speed <key>` measures throughput to them. Every verb speaks
//! from the same persisted identity, so this node has one address across all of them, AND across
//! transports: `--transport iroh|quirk` swaps the backend underneath without changing the address. iris
//! and tightbeam verbs (`send`/`recv`/`tunnel`) land next; see the README.

use bifrost::{Discovery, NoDiscovery, Node, Transport};
use clap::{Parser, Subcommand};

mod commands;
mod identity;
mod transport;

use commands::ping::PingCmd;
use commands::serve::ServeCmd;
use commands::speed::SpeedCmd;
use transport::Peer;

/// The unified front door to the theia overlay: reach, name, and run code at a public key.
#[derive(Debug, Parser)]
#[command(name = "swoosh", version, about)]
struct Cli {
    /// Which transport to bind under the shared identity. iroh self-discovers; quirk is direct-only
    /// and pairs with `--peer` hints. The NodeId is identical whichever is chosen. Global, so it may
    /// sit before or after the verb.
    #[arg(long, value_enum, default_value_t, global = true)]
    transport: transport::Transport,
    /// A direct address hint for quirk, `<key>=<socketaddr>`, repeatable. Ignored by iroh, which
    /// self-discovers. Feed back what a peer's `swoosh serve` prints. Global, so it may sit after the
    /// verb next to the peer key it hints.
    #[arg(long, global = true)]
    peer: Vec<Peer>,
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
}

impl Command {
    /// Run the selected verb against the composed node. Every verb is generic over `Node<T, D>`, so
    /// this dispatch is transport-blind: the concrete transport was chosen once, at the seam below.
    async fn run<T: Transport, D: Discovery>(self, node: &Node<T, D>) -> eyre::Result<()> {
        match self {
            Self::Serve(cmd) => cmd.run(node).await,
            Self::Ping(cmd) => cmd.run(node).await,
            Self::Speed(cmd) => cmd.run(node).await,
        }
    }
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    // The one and only place a concrete transport is named. Everything downstream speaks `bifrost`.
    // The identity is persisted and shared across every verb and every transport, so this node keeps
    // one address across runs, commands, and backends: the same key yields the same NodeId whether it
    // is bound under iroh or quirk, which is what makes the transport swap a swap and not a new node.
    let secret = identity::load_or_create().await?;
    match cli.transport {
        // iroh self-discovers (n0 pkarr/DNS + relays), so it composes with NoDiscovery and ignores
        // `--peer`. Unchanged from the iroh-only skeleton.
        transport::Transport::Iroh => {
            let node = Node::new(
                bifrost_iroh::Endpoint::bind_with_secret(secret.into_bytes()).await?,
                NoDiscovery,
            );
            cli.command.run(&node).await
        }
        // quirk is direct-only with no internal discovery, so it composes with a StaticDiscovery
        // seeded from the `--peer` hints. A client dials a peer by feeding back the `<key>=<addr>`
        // that peer's `serve` prints.
        transport::Transport::Quirk => {
            let node = Node::new(
                bifrost_quirk::Endpoint::bind_with_secret(secret.into_bytes()).await?,
                Peer::discovery(cli.peer),
            );
            cli.command.run(&node).await
        }
    }
}
