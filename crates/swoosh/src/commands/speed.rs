//! `swoosh speed <peer>`: measure throughput to a peer over the overlay, iperf-shaped. One direction at
//! a time (`--up` or `--down`, default down) or both at once (`--bidir`), bounded by time (`-t`) or
//! bytes (`-n`, default `-t 5`).
//!
//! One target, unlike `ping`/`status`: a speed test saturates a link, so fanning out over a person's
//! devices would just contend for the one uplink and have no single number to report. A bare person
//! (`alice`) dials her first reachable device; `alice/macbook` picks the one. The header names the
//! connection path (direct vs relayed, the same source `status` reads) so a slow number reads as "it
//! relayed", not a mystery, and throughput prints OVER TIME: a line per interval as it runs, then the
//! per-direction totals.

use core::time::Duration;
use std::time::Instant;

use bifrost::{Discovery, Node, Session, Transport};
use clap::{ArgGroup, Args};
use diag::{Limit, Mode, Progress, SpeedReport, Speedtest, Throughput};

use crate::contacts::{Contacts, Target};
use crate::reach::{self, Reached};
use crate::transport::{self, ReachArgs};

/// How often a running speed test prints its current rate. One second matches iperf's default report
/// interval and reads as a live, once-a-second heartbeat without flooding the terminal.
const REPORT_INTERVAL: Duration = Duration::from_secs(1);

/// Measure throughput to a peer: iperf, but over the overlay.
#[derive(Debug, Args)]
#[command(group = ArgGroup::new("way").args(["up", "down", "bidir"]))]
#[command(group = ArgGroup::new("bound").args(["secs", "bytes"]))]
pub struct SpeedCmd {
    /// The peer to reach: a saved petname (`alice`, `alice/macbook`) or a raw bifrost node id.
    #[arg(value_name = "peer")]
    pub target: Target,
    /// Measure the upload direction (this node sends).
    #[arg(long)]
    pub up: bool,
    /// Measure the download direction (this node receives).
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
    #[command(flatten)]
    pub reach: ReachArgs,
}

impl SpeedCmd {
    /// Dial the first reachable device, print the path header, then run the transfer while a ticker
    /// prints the rate each interval, and finish with the per-direction totals.
    pub async fn run<T: Transport, D: Discovery>(
        self,
        node: &Node<T, D>,
        contacts: &Contacts,
        transport: transport::Transport,
    ) -> eyre::Result<()> {
        let mode = self.mode();
        let limit = self.limit();
        let Reached { session, label } =
            reach::dial(node, contacts, &self.target, transport).await?;
        let path = reach::conn_path(&session.conn_info());
        println!(
            "speed test to {label} via {}: {path} ({})",
            transport.name(),
            mode.label()
        );

        // A shared counter the transfer bumps and the ticker reads, so the rate prints live rather than
        // only at the end. The ticker runs until the transfer finishes and drops its end of the channel.
        let progress = Progress::new();
        let report = {
            let ticker = report_over_time(progress.clone());
            let test = Speedtest::new(mode, limit)
                .tracking(progress.clone())
                .run(&session);
            // Race the transfer against the ticker: the transfer completes, the ticker loops forever, so
            // select ends the ticker the moment the run returns.
            tokio::select! {
                report = test => report?,
                never = ticker => match never {},
            }
        };

        // Drain and close the transport so the last frames land and iroh shuts down cleanly.
        node.close().await;
        print_totals(&report);
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

/// Print the rate over each [`REPORT_INTERVAL`] until cancelled: the bytes moved since the last tick as
/// a MiB/s line. Never returns (its result is [`core::convert::Infallible`]); the caller races it against the
/// transfer and drops it when the run finishes, so the last partial interval is covered by the totals.
async fn report_over_time(progress: Progress) -> core::convert::Infallible {
    let started = Instant::now();
    let mut ticker = tokio::time::interval(REPORT_INTERVAL);
    ticker.tick().await; // The first tick fires immediately; skip it so the first line is one interval in.
    let mut last_bytes = 0u64;
    let mut last_at = started;
    loop {
        ticker.tick().await;
        let now = Instant::now();
        let bytes = progress.bytes();
        let delta = bytes - last_bytes;
        let secs = now.duration_since(last_at).as_secs_f64();
        println!(
            "  {:>5.1}s  {}",
            now.duration_since(started).as_secs_f64(),
            rate(delta, secs)
        );
        last_bytes = bytes;
        last_at = now;
    }
}

/// Print the final totals: one line per direction the run measured, direction-labelled and aligned so a
/// `--bidir` run stacks cleanly.
fn print_totals(report: &SpeedReport) {
    let elapsed = report.elapsed().as_secs_f64();
    if let Some(up) = report.up() {
        print_leg("up", up, elapsed);
    }
    if let Some(down) = report.down() {
        print_leg("down", down, elapsed);
    }
}

/// Print one direction's total: bytes moved over the whole window and the average rate.
fn print_leg(direction: &str, leg: Throughput, elapsed: f64) {
    println!(
        "{:<4}  {} in {elapsed:.2}s = {:.2} MiB/s",
        direction,
        mib(leg.bytes()),
        leg.mib_per_sec(),
    );
}

/// A per-interval rate as MiB/s, from bytes moved over a span. Zero if no time elapsed.
fn rate(bytes: u64, secs: f64) -> String {
    let mib_per_sec = if secs > 0.0 {
        (bytes as f64 / (1024.0 * 1024.0)) / secs
    } else {
        0.0
    };
    format!("{mib_per_sec:.2} MiB/s")
}

/// A byte count rendered as mebibytes.
fn mib(bytes: u64) -> String {
    format!("{:.2} MiB", bytes as f64 / (1024.0 * 1024.0))
}
