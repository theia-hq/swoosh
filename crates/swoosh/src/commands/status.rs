//! `swoosh status <key>`: dial a peer and report the connection path, Tailscale `status` shaped.
//!
//! The single most reassuring thing a p2p tool tells you: am I actually peer to peer, or bouncing off a
//! relay? This dials the peer, reads the session's best-effort [`conn_info`](bifrost::Session::conn_info)
//! for the path (direct vs relayed) and remote address, and runs a single diag ping for a live RTT,
//! then prints one line. Over quirk it says direct; over iroh it reports the current path, which can
//! start relayed and upgrade to direct as hole-punching completes. Honest when the transport cannot
//! tell.
//!
//! One-shot: swoosh has no daemon, so this reports the one peer you dial. Listing the whole tailnet of
//! active sessions (Tailscale's full `status`) needs a long-lived node holding those sessions; that is
//! future work, sequenced behind a swoosh daemon.

use core::time::Duration;

use bifrost::{ConnInfo, Discovery, Node, NodeId, Path, Session, Transport};
use clap::Args;
use diag::Ping;

use crate::transport;

/// Report the connection path to a peer: transport, direct vs relayed, remote address, and live RTT.
#[derive(Debug, Args)]
pub struct StatusCmd {
    /// The peer to reach, as a bifrost node id.
    pub key: NodeId,
}

impl StatusCmd {
    /// Dial the peer, probe the path and a single RTT, and print the status line.
    pub async fn run<T: Transport, D: Discovery>(
        self,
        node: &Node<T, D>,
        transport: transport::Transport,
    ) -> eyre::Result<()> {
        let session = node.connect(self.key).await?;
        let info = session.conn_info();

        // A single diag ping for a fresh, honest RTT. Some transports (quirk) carry no rtt estimator, so
        // conn_info().rtt is None there; one probe measures the round trip the same way over any of them.
        let probed = Ping {
            count: 1,
            interval: Duration::ZERO,
        }
        .run(&session)
        .await?;
        let rtt = probed.avg().or(info.rtt);

        node.close().await;
        println!("{}", Line::new(self.key, transport.name(), info, rtt));
        Ok(())
    }
}

/// A rendered status line: the peer, the transport, the path, remote, and RTT.
struct Line {
    peer: NodeId,
    transport: &'static str,
    info: ConnInfo,
    rtt: Option<Duration>,
}

impl Line {
    fn new(peer: NodeId, transport: &'static str, info: ConnInfo, rtt: Option<Duration>) -> Self {
        Self {
            peer,
            transport,
            info,
            rtt,
        }
    }
}

impl core::fmt::Display for Line {
    /// `<peer> via <transport>: <path>[, <rtt>]`, Tailscale-status shaped. The path phrase names the
    /// remote when a direct address is known and notes that a relayed iroh path may still upgrade.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{} via {}: {}",
            self.peer.short(),
            self.transport,
            path(&self.info)
        )?;
        if let Some(rtt) = self.rtt {
            write!(f, ", rtt {:.3} ms", rtt.as_secs_f64() * 1000.0)?;
        }
        Ok(())
    }
}

/// The path phrase for a status line, from the best-effort [`ConnInfo`].
fn path(info: &ConnInfo) -> String {
    match info.path {
        Path::Direct => match info.remote {
            Some(remote) => format!("direct to {remote}"),
            None => "direct".to_owned(),
        },
        // A relayed iroh path is honest about being able to upgrade: hole-punching may still complete
        // and move this to direct, so a re-run can report a different path.
        Path::Relayed => "relayed (may upgrade to direct)".to_owned(),
        Path::Mixed => match info.remote {
            Some(remote) => format!("mixed (direct to {remote} and relayed)"),
            None => "mixed (direct and relayed)".to_owned(),
        },
        // The transport does not expose its path (in-process, or not yet instrumented). Say so rather
        // than fabricating a reassuring answer.
        Path::Unknown => "path unknown".to_owned(),
    }
}
