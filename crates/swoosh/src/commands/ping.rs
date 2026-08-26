//! `swoosh ping <key>`: reach a peer by their public key and report round-trip time, `ping(8)` shaped.

use core::time::Duration;

use bifrost::{Discovery, Node, NodeId, Transport};
use clap::Args;
use diag::{Ping, PingReport};

/// Measure the round-trip time to a peer, addressed by their public key.
#[derive(Debug, Args)]
pub struct PingCmd {
    /// The peer to reach, as a bifrost node id.
    pub key: NodeId,
    /// How many probes to send.
    #[arg(short = 'c', long, default_value_t = 4)]
    pub count: u32,
    /// Seconds between probes.
    #[arg(short = 'i', long, default_value_t = 1.0)]
    pub interval: f64,
}

impl PingCmd {
    /// Dial the peer, run the probes, and print the summary.
    pub async fn run<T: Transport, D: Discovery>(self, node: &Node<T, D>) -> eyre::Result<()> {
        let session = node.connect(self.key).await?;
        println!("pinging {} ({} probes)", self.key.short(), self.count);

        let report = Ping {
            count: self.count,
            interval: Duration::from_secs_f64(self.interval),
        }
        .run(&session)
        .await?;

        // Drain and close the transport so the last frames land and iroh shuts down cleanly.
        node.close().await;
        print_report(&report);
        Ok(())
    }
}

/// Print the `ping(8)`-style summary: counts, loss, and the RTT distribution.
fn print_report(report: &PingReport) {
    let loss_pct = report.loss() * 100.0;
    println!(
        "{} probes sent, {} replies, {loss_pct:.0}% loss",
        report.sent(),
        report.received()
    );
    if let (Some(min), Some(avg), Some(max), Some(mdev)) =
        (report.min(), report.avg(), report.max(), report.mdev())
    {
        println!(
            "rtt min/avg/max/mdev = {:.3}/{:.3}/{:.3}/{:.3} ms",
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
