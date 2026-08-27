//! `swoosh speed <key>`: measure throughput to a peer over the overlay, iperf-shaped. One direction at
//! a time (`--up` or `--down`, default down) or both at once (`--bidir`), bounded by time (`-t`) or
//! bytes (`-n`, default `-t 5`).

use core::time::Duration;

use bifrost::{Discovery, Node, NodeId, Transport};
use clap::{ArgGroup, Args};
use diag::{Limit, Mode, SpeedReport, Speedtest, Throughput};

/// Measure throughput to a peer: iperf, but over the overlay.
#[derive(Debug, Args)]
#[command(group = ArgGroup::new("way").args(["up", "down", "bidir"]))]
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
    /// Measure upload and download at once, full-duplex on one stream. Works over quirk too.
    #[arg(long)]
    pub bidir: bool,
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
        let mode = self.mode();
        let limit = self.limit();
        let session = node.connect(self.key).await?;
        println!("speed test to {} ({})", self.key.short(), label(mode));

        let report = Speedtest { mode, limit }.run(&session).await?;

        // Drain and close the transport so the last frames land and iroh shuts down cleanly.
        node.close().await;
        print_report(&report);
        Ok(())
    }

    /// What to measure: `--up`, `--bidir`, or download (the group makes more than one impossible).
    fn mode(&self) -> Mode {
        if self.up {
            Mode::Up
        } else if self.bidir {
            Mode::Bidir
        } else {
            Mode::Down
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

/// Print the throughput summary: one line per direction the run measured.
fn print_report(report: &SpeedReport) {
    let elapsed = report.elapsed().as_secs_f64();
    if let Some(up) = report.up() {
        print_leg("up", up, elapsed);
    }
    if let Some(down) = report.down() {
        print_leg("down", down, elapsed);
    }
}

/// Print one direction's throughput line.
fn print_leg(direction: &str, leg: Throughput, elapsed: f64) {
    println!(
        "{} {} in {elapsed:.2}s = {:.2} MiB/s",
        direction,
        mib(leg.bytes()),
        leg.mib_per_sec(),
    );
}

/// A human label for a mode.
fn label(mode: Mode) -> &'static str {
    match mode {
        Mode::Up => "up",
        Mode::Down => "down",
        Mode::Bidir => "bidir",
    }
}

/// A byte count rendered as mebibytes.
fn mib(bytes: u64) -> String {
    format!("{:.2} MiB", bytes as f64 / (1024.0 * 1024.0))
}
