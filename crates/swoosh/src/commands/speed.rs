//! `swoosh speed <key>`: measure throughput to a peer over the overlay, iperf-shaped. One direction at
//! a time (`--up` or `--down`, default down), bounded by time (`-t`) or bytes (`-n`, default `-t 5`).

use core::time::Duration;

use bifrost::{Discovery, Node, NodeId, Transport};
use clap::{ArgGroup, Args};
use diag::{Direction, Limit, SpeedReport, Speedtest};

/// Measure throughput to a peer: iperf, but over the overlay.
#[derive(Debug, Args)]
#[command(group = ArgGroup::new("way").args(["up", "down"]))]
#[command(group = ArgGroup::new("bound").args(["secs", "bytes"]))]
pub struct SpeedCmd {
    /// The peer to reach, as a bifrost node id.
    pub key: NodeId,
    /// Measure the upload direction (this node sends).
    #[arg(long)]
    pub up: bool,
    /// Measure the download direction (this node receives). The default.
    #[arg(long)]
    pub down: bool,
    /// Run for this many seconds. Defaults to 5 when no bound is given.
    #[arg(short = 't', long)]
    pub secs: Option<f64>,
    /// Transfer this many bytes instead of running for a fixed time.
    #[arg(short = 'n', long)]
    pub bytes: Option<u64>,
}

impl SpeedCmd {
    /// Dial the peer, run the transfer, and print the throughput.
    pub async fn run<T: Transport, D: Discovery>(self, node: &Node<T, D>) -> eyre::Result<()> {
        let direction = self.direction();
        let limit = self.limit();
        let session = node.connect(self.key).await?;
        println!("speed test to {} ({})", self.key.short(), label(direction));

        let report = Speedtest { direction, limit }.run(&session).await?;

        // Drain and close the transport so the last frames land and iroh shuts down cleanly.
        node.close().await;
        print_report(&report);
        Ok(())
    }

    /// The direction to measure: `--up` if asked, otherwise download (the group makes both impossible).
    fn direction(&self) -> Direction {
        if self.up {
            Direction::Up
        } else {
            Direction::Down
        }
    }

    /// The stop condition: an explicit byte count, else an explicit or default duration.
    fn limit(&self) -> Limit {
        match (self.bytes, self.secs) {
            (Some(bytes), _) => Limit::ByBytes(bytes),
            (None, Some(secs)) => Limit::ByTime(Duration::from_secs_f64(secs)),
            (None, None) => Limit::ByTime(Duration::from_secs(5)),
        }
    }
}

/// Print the throughput summary for a finished transfer.
fn print_report(report: &SpeedReport) {
    println!(
        "{} in {:.2}s = {:.2} MiB/s ({})",
        mib(report.bytes()),
        report.elapsed().as_secs_f64(),
        report.mib_per_sec(),
        label(report.direction()),
    );
}

/// A human label for a direction.
fn label(direction: Direction) -> &'static str {
    match direction {
        Direction::Up => "up",
        Direction::Down => "down",
    }
}

/// A byte count rendered as mebibytes.
fn mib(bytes: u64) -> String {
    format!("{:.2} MiB", bytes as f64 / (1024.0 * 1024.0))
}
