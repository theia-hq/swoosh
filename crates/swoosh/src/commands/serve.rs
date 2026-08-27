//! `swoosh serve`: be online. Print this node's address, then accept sessions and answer each peer's
//! reach diagnostics with the diag [`Responder`]. This is the peer a `swoosh ping` / `swoosh speed`
//! client dials.

use bifrost::{Discovery, Node, Session, Transport};
use clap::Args;
use diag::Responder;
use futures::StreamExt as _;
use futures::stream::FuturesUnordered;

use crate::transport::ReachArgs;

/// Answer reach diagnostics from peers until interrupted.
#[derive(Debug, Args)]
pub struct ServeCmd {
    #[command(flatten)]
    pub reach: ReachArgs,
}

impl ServeCmd {
    /// Accept sessions and serve each concurrently; a Ctrl-C ends the loop gracefully.
    pub async fn run<T: Transport, D: Discovery>(self, node: &Node<T, D>) -> eyre::Result<()> {
        let addr = node.local_addr();
        println!("swoosh ready. peers can reach this node at:\n");
        println!("    {}\n", addr.node);
        // Direct-only transports (quirk) cannot discover this address, so print the dialable hint a
        // client feeds back via `--peer`. Self-discovering transports (iroh) carry no local hints
        // here, so this loop prints nothing for them.
        for hint in &addr.hints {
            println!("    --peer {}={hint}\n", addr.node);
        }
        println!("answering ping and speed. press ctrl-c to stop.");

        let mut sessions = FuturesUnordered::new();
        loop {
            tokio::select! {
                accepted = node.accept() => {
                    // The listener outlives any one peer: a transient accept error must not tear down
                    // the sessions already being served, so log it and keep accepting.
                    let session = match accepted {
                        Ok(session) => session,
                        Err(error) => {
                            tracing::warn!(%error, "accept failed; still listening");
                            continue;
                        }
                    };
                    tracing::info!(peer = %session.peer(), "serving diagnostics");
                    sessions.push(Responder::serve(session));
                }
                Some(()) = sessions.next(), if !sessions.is_empty() => {}
                result = tokio::signal::ctrl_c() => {
                    result?;
                    println!("\nshutting down.");
                    node.close().await;
                    return Ok(());
                }
            }
        }
    }
}
