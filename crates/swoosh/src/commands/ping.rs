//! `swoosh ping <peer>`: reach a peer by petname or public key and report round-trip time, `ping(8)`
//! shaped.
//!
//! ping is a diagnostic, so a person (`alice`) fans out to ALL her devices and reports each: how do I
//! reach alice, across every device she has? `alice/macbook` pings the one. Each device's block leads
//! with the connection path (direct vs relayed, the same source `status` reads) so a slow RTT reads as
//! "it relayed", not a mystery, then the `ping(8)` counts/loss and RTT distribution.

use core::time::Duration;

use bifrost::{Discovery, Node, Session, Transport};
use clap::Args;
use diag::{Ping, PingReport};

use crate::contacts::{Contacts, Target};
use crate::reach;
use crate::transport::{self, ReachArgs};

/// Measure the round-trip time to a peer, addressed by a petname or their public key.
#[derive(Debug, Args)]
pub struct PingCmd {
    /// The peer to reach: a saved petname (`alice`, `alice/macbook`) or a raw bifrost node id.
    #[arg(value_name = "peer")]
    pub target: Target,
    /// How many probes to send.
    #[arg(short = 'c', long, default_value_t = 4)]
    pub count: u32,
    /// Seconds between probes.
    #[arg(short = 'i', long, default_value_t = 1.0)]
    pub interval: f64,
    #[command(flatten)]
    pub reach: ReachArgs,
}

impl PingCmd {
    /// Resolve the target to its devices, and for each dial, probe, and print its path and RTT summary.
    /// Reports every device (a person fans out); an unreachable one prints an honest line and the run
    /// continues, ending non-zero only if no device answered at all.
    pub async fn run<T: Transport, D: Discovery>(
        self,
        node: &Node<T, D>,
        contacts: &Contacts,
        transport: transport::Transport,
    ) -> eyre::Result<()> {
        let candidates = reach::candidates(&self.target, contacts)?;
        let plan = Ping {
            count: self.count,
            interval: Duration::from_secs_f64(self.interval),
        };

        let mut any_reached = false;
        for candidate in &candidates {
            match reach::connect(node, candidate).await {
                Ok(session) => {
                    any_reached = true;
                    let report = plan.run(&session).await?;
                    let path = reach::conn_path(&session.conn_info());
                    print_device(&candidate.label, transport.name(), &path, &report);
                }
                Err(_error) => {
                    println!("{} via {}: unreachable", candidate.label, transport.name());
                }
            }
        }

        // Drain and close the transport so the last frames land and iroh shuts down cleanly.
        node.close().await;
        if any_reached {
            Ok(())
        } else {
            Err(reach::hint(
                eyre::eyre!("could not reach {}", self.target),
                transport,
            ))
        }
    }
}

/// Print one device's block: the path line (status-shaped), then the `ping(8)` counts and RTT
/// distribution indented beneath it.
fn print_device(label: &str, transport: &str, path: &str, report: &PingReport) {
    println!("{label} via {transport}: {path}");
    let loss_pct = report.loss() * 100.0;
    println!(
        "  {} sent, {} received, {loss_pct:.0}% loss",
        report.sent(),
        report.received()
    );
    if let (Some(min), Some(avg), Some(max), Some(mdev)) =
        (report.min(), report.avg(), report.max(), report.mdev())
    {
        println!(
            "  rtt min/avg/max/mdev = {:.3}/{:.3}/{:.3}/{:.3} ms",
            millis(min),
            millis(avg),
            millis(max),
            millis(mdev),
        );
    }
}

/// A duration as fractional milliseconds, the unit ping reports.
fn millis(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}
