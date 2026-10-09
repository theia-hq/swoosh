//! `swoosh speed <peer>`: measure throughput to a peer over the overlay, iperf-shaped. One direction at
//! a time (`--up` or `--down`, default down) or both at once (`--bidir`), bounded by time (`-t`) or
//! bytes (`-n`, default `-t 5`).
//!
//! One machine: `alice/macbook` picks that one, and a bare person dials their one saved machine (several
//! refuse before anything binds). Throughput prints OVER
//! TIME: a line per interval as it runs, then the per-direction totals. The connection path (direct vs
//! relayed, the same source `status` reads) is reported after the transfer, since the run is the window
//! in which a relayed iroh link may hole-punch up to direct: a slow number then reads as "it relayed",
//! not a mystery.

use core::time::Duration;
use std::time::Instant;

use bifrost::{Discovery, Node, Session, Transport};
use clap::{ArgGroup, Args};
use measure::{
    Limit, MethodRefusal, Mode, Progress, ProtocolError, Refusal, SpeedReport, Speedtest,
    Throughput,
};
use nauthy::{Link, Service};
use swoosh::escape::{Escaped, causes};
use swoosh::learn::Admitted;
use swoosh::peer::{Machine, Peer};
use swoosh::reach;
use swoosh::transport::{self, ReachArgs};

use crate::commands::machine;

/// How often a running speed test prints its current rate. One second matches iperf's default report
/// interval and reads as a live, once-a-second heartbeat without flooding the terminal.
const REPORT_INTERVAL: Duration = Duration::from_secs(1);

/// Measure throughput to a peer: iperf, but over the overlay.
#[derive(Debug, Args)]
#[command(group = ArgGroup::new("way").args(["up", "down", "bidir"]))]
#[command(group = ArgGroup::new("bound").args(["secs", "bytes"]))]
pub struct SpeedCmd {
    #[arg(value_name = "machine", help = machine::HELP)]
    pub peer: Peer,
    /// Measure the upload direction (this node sends).
    #[arg(long)]
    pub up: bool,
    /// Measure the download direction (this node receives).
    #[arg(long)]
    pub down: bool,
    /// Measure upload and download at once, full-duplex on one stream. Works over quirk too.
    #[arg(long)]
    pub bidir: bool,
    /// How long to run, in seconds (5 unless -n is given)
    #[arg(short = 't', long, value_name = "s")]
    pub secs: Option<f64>,
    /// Transfer this many bytes instead of running for a fixed time.
    #[arg(short = 'n', long, value_name = "bytes")]
    pub bytes: Option<u64>,
    #[command(flatten)]
    pub reach: ReachArgs,
}

impl swoosh::reaching::Reaching for SpeedCmd {
    fn reach_args(&self) -> &swoosh::transport::ReachArgs {
        &self.reach
    }

    /// The peer this verb dials, for the stale-list exchange after it runs.
    fn dialed(&self) -> Option<&swoosh::peer::Peer> {
        Some(&self.peer)
    }

    fn identity(&self) -> swoosh::identity::Identity {
        self.bind_role().identity()
    }

    /// Dialing, and what it dials as. It reaches a peer and never accepts connections under the
    /// home key, so its bind must not write the key's address record (0.9.0 F1).
    ///
    /// `speed` reaches the peer's family-gated `speed` service, so it presents the member badge rooted at
    /// the dialing key (like `ping`). `Family` fuses the identity to `PersistedIfPresent`. A
    /// self-addressing `swoosh:` link-as-peer is threaded INTO the credential so the ONE resolver owns both
    /// slots.
    ///
    /// An `anyone` link typed as the peer presents alone, under a throwaway key (`Credential::dialing`).
    fn bind_role(&self) -> swoosh::reaching::BindRole {
        swoosh::reaching::BindRole::Dialing(swoosh::credential::Credential::dialing(
            &self.peer,
            reach::SPEED_SERVICE,
        ))
    }

    /// Uniform dispatch: unpack the reach context and run. `speed` reads the resolved machine, the
    /// `transport` label, and the resolved `present` badge.
    async fn run<T: Transport, D: Discovery>(
        self,
        node: &Node<T, D>,
        ctx: swoosh::reaching::ReachCtx<'_>,
    ) -> eyre::Result<()>
    where
        <T::Session as Session>::Write: Send + 'static,
        <T::Session as Session>::Read: Send + 'static,
    {
        let Some(machine) = ctx.machine else {
            eyre::bail!("internal: `speed` ran without its machine resolved (root-dispatch bug)");
        };
        self.run_speed(
            node,
            machine,
            ctx.bound,
            ctx.present,
            ctx.membership,
            ctx.admitted,
        )
        .await
    }
}

impl SpeedCmd {
    /// Dial the machine, run the transfer while a ticker prints the rate each interval,
    /// then report the settled connection path and the per-direction totals.
    async fn run_speed<T: Transport, D: Discovery>(
        self,
        node: &Node<T, D>,
        machine: &Machine,
        bound: &transport::Bound,
        present: Option<Link>,
        membership: Option<Link>,
        admitted: Admitted,
    ) -> eyre::Result<()> {
        let mode = self.mode();
        let limit = self.limit();
        // Slots 1 and 2 are ALREADY resolved by the composition root's ONE resolver (link-or-badge in
        // slot 1, a fleet badge in slot 2 only for a signet-bound slip); the fold in `bind_role()` routed a
        // link-as-peer through that same resolver, so the verb never threads a slip itself.
        let service: Service = reach::SPEED_SERVICE.parse()?;
        let session = reach::dial_service(
            node,
            machine,
            &self.peer,
            &service,
            Option::clone(&present),
            Option::clone(&membership),
            bound,
        )
        .await?;
        // Its first admitted stream tells the composition root it may ask which root vouches for the machine.
        let session = admitted.watch(session);
        let label = machine.label();
        println!(
            "speed test to {label} via {} ({})",
            bound.transport.name(),
            mode.label()
        );

        // A shared counter the transfer bumps and the ticker reads, so the rate prints live rather than
        // only at the end. The ticker runs until the transfer finishes and drops its end of the channel.
        let progress = Progress::new();
        let outcome = {
            let ticker = report_over_time(progress.clone());
            let test = Speedtest::new(mode, limit)
                .tracking(progress.clone())
                .run(&session);
            // Race the transfer against the ticker: the transfer completes, the ticker loops forever, so
            // select ends the ticker the moment the run returns.
            tokio::select! {
                report = test => report,
                never = ticker => match never {},
            }
        };
        // A refusal is a LOUD, distinct error, never `0.00 MiB/s`: the node reached us but refused the
        // run, so name what refused it (a missing method, a rate limit, a busy service) rather than
        // reporting a zero-byte transfer over the elapsed window. A Layer-2 method refusal means the
        // stream was admitted but not the method; anything else (a Layer-1 gate refusal) means the dial
        // itself was refused.
        let report = match outcome {
            Ok(report) => report,
            // The machine refused this machine the service: the dial refusal, once. One of your devices is
            // asked why first, over a second connection, since the gated session opens nothing but `speed`.
            Err(ProtocolError::Refused(Refusal::Stream(bifrost::Refusal::NotAdmitted))) => {
                let diagnosis =
                    reach::diagnose_over(node, machine, &service, present, membership).await;
                return Err(machine::refused(machine, &service, diagnosis));
            }
            Err(ProtocolError::Refused(refusal)) => {
                let line = refusal_line(&label, &refusal);
                eyre::bail!("{line}");
            }
            Err(error) => {
                eyre::bail!("{}", failed_line(&error));
            }
        };

        // Read the settled path now: the transfer gave hole-punching time to land. The composition root
        // closes the node once anything still running beside the verb has ended.
        let path = reach::conn_path(&session.conn_info()).to_string();
        println!("path: {path}");
        print_totals(&report);
        Ok(())
    }
}

impl SpeedCmd {
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

/// The one line a `speed` refusal renders. After admission the typed code chooses the phrase, never the
/// detail prose: `WrongMethod` names the method the peer does not serve; `RateLimited` and `Busy` name the
/// bound that stopped the run, so a capped run never reads as a missing service (the render table in
/// `notes/design/typed-refusal-and-errors.md`). A new code breaks this match at compile time. A refusal
/// of the dial itself says it was reached and refused. The detail is the peer's text, so it prints
/// through the escaper.
fn refusal_line(label: &str, refusal: &Refusal) -> String {
    let Refusal::Method { code, detail } = refusal else {
        return format!(
            "{label}: reached, but refused: {}",
            Escaped(&refusal.to_string())
        );
    };
    let detail = Escaped(detail.as_str());
    match code {
        MethodRefusal::WrongMethod => format!("{label} does not serve `speed`: {detail}"),
        MethodRefusal::RateLimited => format!("{label} is rate limited: {detail}"),
        MethodRefusal::Busy => format!("{label} is busy: {detail}"),
    }
}

/// The line for a run that was reached and then broke: the error's cause chain, `outer: inner`, as a
/// report would print it. A cause can carry the peer's text (the reason it gave for closing), so the
/// chain prints through the escaper.
fn failed_line(error: &ProtocolError) -> String {
    Escaped(&causes(error)).to_string()
}

#[cfg(test)]
#[path = "speed_tests.rs"]
mod speed_tests;
