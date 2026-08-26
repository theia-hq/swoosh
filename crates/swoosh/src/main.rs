//! swoosh: one command, one identity, every p2p operation as a verb.
//!
//! `swoosh serve` makes this node answer reach diagnostics; `swoosh ping <key>` measures the round trip
//! to a peer by their public key; `swoosh speed <key>` measures throughput to them. Every verb speaks
//! from the same persisted identity, so this node has one address across all of them. iris and
//! tightbeam verbs (`send`/`recv`/`tunnel`) land next; see the README.

use bifrost::{NoDiscovery, Node};
use clap::{Parser, Subcommand};

mod commands;
mod identity;

use commands::ping::PingCmd;
use commands::serve::ServeCmd;
use commands::speed::SpeedCmd;

/// The unified front door to the theia overlay: reach, name, and run code at a public key.
#[derive(Debug, Parser)]
#[command(name = "swoosh", version, about)]
struct Cli {
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

#[tokio::main]
async fn main() -> eyre::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    // The one and only place a concrete transport is named. Everything downstream speaks `bifrost`.
    // iroh self-discovers (n0 pkarr/DNS + relays), so it composes with NoDiscovery. The identity is
    // persisted and shared across every verb, so this node keeps one address across runs and commands.
    let secret = identity::load_or_create().await?;
    let node = Node::new(
        bifrost_iroh::Endpoint::bind_with_secret(secret).await?,
        NoDiscovery,
    );

    match cli.command {
        Command::Serve(cmd) => cmd.run(&node).await,
        Command::Ping(cmd) => cmd.run(&node).await,
        Command::Speed(cmd) => cmd.run(&node).await,
    }
}
