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
//!
//! The run is one stream on a connection of its own, never a held session, so the rate and the path are
//! this run's. By own bind the path is read from that connection after the transfer, while it is still
//! open; while `swoosh serve` runs here, the stream is one observed Open through it, the path sampled
//! there each second beside the run and read once more by a Finish after it.

use core::convert::Infallible;
use core::time::Duration;
use std::io::{self, Write};
use std::time::Instant;

use bifrost::{ConnInfo, Session};
use clap::{ArgGroup, Args};
use measure::{
    Limit, MethodRefusal, Mode, Progress, ProtocolError, Refusal, SpeedReport, Speedtest,
    Throughput,
};
use nauthy::Service;
use swoosh::escape::{Escaped, causes};
use swoosh::learn::Admitted;
use swoosh::observation::{Follow, Observed};
use swoosh::peer::{Machine, Peer};
use swoosh::peers::Hints;
use swoosh::reach;
use swoosh::serve::control_codec::{OpenLane, OpenRefusal, PeerRefusal};
use swoosh::streams::{Ask, Observing, Unopened};
use swoosh::transport::ReachArgs;

use crate::commands::route::Route;
use crate::commands::{machine, through_serve};

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
    /// Measure upload and download at once, full-duplex on one stream.
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
        swoosh::reaching::BindRole::Dialing(self.credential())
    }
}

impl SpeedCmd {
    /// What this run dials as: the one value that picks its bind and what its stream presents.
    pub(crate) fn credential(&self) -> swoosh::credential::Credential {
        swoosh::credential::Credential::dialing(&self.peer, reach::SPEED_SERVICE)
    }

    /// Measure throughput to `machine` over one stream from `source` on a connection of its own,
    /// printing on `out` and `err`, as `route` words what it meets: the title once the stream is open,
    /// a rate each interval, then the connection's path and the per-direction totals. A machine that
    /// refuses the service `NotAdmitted` prints the refusal as the error, after one of your devices is
    /// asked why through `source`, on Main. Once the stream is admitted, `admitted` gets its question,
    /// asked through `source`.
    ///
    /// # Errors
    ///
    /// The run's line: a refusal, a cut, or `serve` gone.
    pub async fn measure<'s, S: Observing + Copy + 's>(
        &self,
        source: S,
        route: &Route<'_>,
        machine: &Machine,
        admitted: Admitted<'s>,
        out: &mut impl Write,
        err: &mut impl Write,
    ) -> eyre::Result<()> {
        let service: Service = reach::SPEED_SERVICE.parse()?;
        // Isolated, never a held session: the rate and the path line it prints belong to this run's own
        // connection, not to whatever else shares a session to the machine.
        let ask = Ask {
            peer: machine.key(),
            hints: Hints::NONE,
            service: Service::clone(&service),
            lane: OpenLane::Isolated,
            slip: self.peer.self_present(),
        };
        let (session, follow) = match source.observed(&ask).await {
            Ok(observed) => observed,
            Err(Unopened::Refused(OpenRefusal::Peer(PeerRefusal::NotAdmitted))) => {
                let diagnosis = reach::diagnose_through(&source, machine, &service, ask.slip).await;
                return Err(machine::refused(machine, &service, diagnosis));
            }
            Err(unopened) => return Err(route.line(unopened, machine).await),
        };
        admitted.asked_through(source, machine.key());
        let (mode, label) = (self.mode(), machine.label());
        // A title that cannot be written ends the run as a failure, finished all the same.
        if let Err(error) = writeln!(out, "{}", title(&label, mode)) {
            return Err(through_serve::failed(error.into(), follow, err).await);
        }
        observed(
            mode,
            self.limit(),
            &session,
            follow,
            &label,
            async |own| route.cut_or(own).await,
            out,
            err,
        )
        .await
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

/// The line a run prints first, on both paths: the machine and the mode, never the transport, since
/// through `serve` the verb does not know which one carried the run.
fn title(label: &str, mode: Mode) -> String {
    format!("speed test to {label} ({})", mode.label())
}

/// The path row, from a reading of the run's own connection, on both paths.
fn path_line(info: &ConnInfo) -> String {
    format!("path: {}", reach::conn_path(info))
}

/// The transfer over `session`, one stream, beside `observer`, printing on `out` and `err`. A measured
/// run is finished and then prints its path row, read from the run's own connection after the transfer
/// (which gave hole-punching time to land), and its totals; a failed run prints its error first and is
/// finished after. `cut` turns a broken run's own line into the one it prints, asking `serve` whether it
/// stopped.
#[expect(
    clippy::too_many_arguments,
    reason = "the run, its observer and the lines it prints to"
)]
async fn observed<S: Session>(
    mode: Mode,
    limit: Limit,
    session: &S,
    mut observer: impl Follow,
    label: &str,
    cut: impl AsyncFnOnce(eyre::Report) -> eyre::Report,
    out: &mut impl Write,
    err: &mut impl Write,
) -> eyre::Result<()> {
    let report = match transfer(mode, limit, session, observer.moves(|_| {})).await {
        Ok(report) => report,
        Err(ProtocolError::Refused(refusal)) => {
            let line = eyre::eyre!("{}", refusal_line(label, &refusal));
            return Err(through_serve::failed(line, observer, err).await);
        }
        Err(error) => {
            let line = cut(eyre::eyre!("{}", failed_line(&error))).await;
            return Err(through_serve::failed(line, observer, err).await);
        }
    };
    // A path that cannot be read leaves the measured run as it is: the exit stays the run's.
    print_path(observer.finish().await, out, err)?;
    print_totals(&report);
    Ok(())
}

/// Print the path row of a run from its final reading to `out`. When
/// that failed there is no row; `err` carries a warning, and the run's own result and exit stay as they
/// are.
fn print_path(observed: Observed, out: &mut impl Write, err: &mut impl Write) -> io::Result<()> {
    match through_serve::final_path(observed, err)? {
        Some(info) => writeln!(out, "{}", path_line(&info)),
        None => Ok(()),
    }
}

/// Run the transfer over `session` while a ticker prints the rate each interval and `beside` runs with
/// it: the transfer completes, the other two loop forever, so the select ends them the moment it does.
/// A shared counter the transfer bumps and the ticker reads makes the rate print live rather than only
/// at the end.
async fn transfer<S: Session>(
    mode: Mode,
    limit: Limit,
    session: &S,
    beside: impl Future<Output = Infallible>,
) -> Result<SpeedReport, ProtocolError> {
    let progress = Progress::new();
    let ticker = report_over_time(progress.clone());
    let test = Speedtest::new(mode, limit).tracking(progress).run(session);
    tokio::select! {
        report = test => report,
        never = ticker => match never {},
        never = beside => match never {},
    }
}

/// Print the rate over each [`REPORT_INTERVAL`] until cancelled: the bytes moved since the last tick as
/// a MiB/s line. Never returns (its result is [`core::convert::Infallible`]); the caller races it against the
/// transfer and drops it when the run finishes, so the last partial interval is covered by the totals.
async fn report_over_time(progress: Progress) -> Infallible {
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
