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
//! While `swoosh serve` runs here, the run is one observed Open through it on a connection of its own:
//! the path is sampled there each second beside the run and read once more by a Finish after it, so
//! the line names this run's connection at its end. Otherwise the verb binds its own, as before.

use core::convert::Infallible;
use core::time::Duration;
use std::io::{self, Write};
use std::rc::Rc;
use std::time::Instant;

use bifrost::{ConnInfo, Discovery, Node, Session, Transport};
use clap::{ArgGroup, Args};
use measure::{
    Limit, MethodRefusal, Mode, Progress, ProtocolError, Refusal, SpeedReport, Speedtest,
    Throughput,
};
use nauthy::{Link, Service};
use swoosh::contacts::Contacts;
use swoosh::escape::{Escaped, causes};
use swoosh::home::Home;
use swoosh::learn::Admitted;
use swoosh::observation::{Observed, Observer, PathSource};
use swoosh::peer::{Machine, Peer};
use swoosh::reach;
use swoosh::serve::control_codec::OpenLane;
use swoosh::transport::{self, ReachArgs};

use crate::commands::machine;
use crate::commands::through_serve::{self, Dial, Routed};

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
        swoosh::reaching::BindRole::Dialing(swoosh::credential::Credential::dialing(
            &self.peer,
            reach::SPEED_SERVICE,
        ))
    }

    /// Uniform dispatch: unpack the reach context and run. `speed` reads the resolved machine, the
    /// `transport` label, and the resolved `present` badge.
    async fn run<'n: 'p, 'p, T: Transport, D: Discovery>(
        self,
        node: &'n Node<T, D>,
        ctx: swoosh::reaching::ReachCtx<'_>,
        peers: &'p swoosh::peers::Peers<'n, T, D>,
    ) -> eyre::Result<()>
    where
        T::Session: 'static,
        <T::Session as Session>::Write: Send + 'static,
        <T::Session as Session>::Read: Send + 'static,
    {
        let Some(machine) = ctx.machine else {
            eyre::bail!("internal: `speed` ran without its machine resolved (root-dispatch bug)");
        };
        self.run_speed(
            node,
            peers,
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
    /// Dial the machine on a connection of its own, run the transfer while a ticker prints the rate each
    /// interval, then report the settled connection path and the per-direction totals.
    #[expect(
        clippy::too_many_arguments,
        reason = "the uniform reach context, unpacked"
    )]
    async fn run_speed<'n, T: Transport, D: Discovery>(
        self,
        node: &'n Node<T, D>,
        peers: &swoosh::peers::Peers<'n, T, D>,
        machine: &Machine,
        bound: &transport::Bound,
        present: Option<Link>,
        membership: Option<Link>,
        admitted: Admitted,
    ) -> eyre::Result<()>
    where
        T::Session: 'static,
    {
        let mode = self.mode();
        let limit = self.limit();
        // Slots 1 and 2 are ALREADY resolved by the composition root's ONE resolver (link-or-badge in
        // slot 1, a fleet badge in slot 2 only for a signet-bound slip); the fold in `bind_role()` routed a
        // link-as-peer through that same resolver, so the verb never threads a slip itself.
        let service: Service = reach::SPEED_SERVICE.parse()?;
        // Isolated, never a held session: the rate and the path line it prints belong to this run's own
        // connection, not to whatever else shares a session to the machine.
        let session = peers
            .isolated(machine.key(), swoosh::peers::Hints::NONE)
            .await
            .map_err(|error| reach::open_failed(&self.peer, error, bound))?;
        let connector = reach::gated(
            machine.key(),
            Service::clone(&service),
            Option::clone(&present),
            Option::clone(&membership),
        );
        // Its first admitted stream tells the composition root it may ask which root vouches for the machine.
        let session = admitted.watch(session, connector);
        let label = machine.label();
        println!("{}", title(&label, mode));
        let outcome = transfer(mode, limit, &session, core::future::pending()).await;
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
        println!("{}", path_line(&session.conn_info()));
        print_totals(&report);
        Ok(())
    }
}

impl SpeedCmd {
    /// Run through the `serve` at `home` when one answers there: `machine` as resolved, `slip` the link
    /// typed as it, if one was, and `contacts` to name it in a cut's line.
    ///
    /// # Errors
    ///
    /// The control socket cannot be trusted; never an own bind then.
    pub async fn through_serve(
        &self,
        home: &Home,
        machine: &Machine,
        slip: Option<Link>,
        contacts: &Contacts,
    ) -> eyre::Result<Routed> {
        let Some((socket, connected)) = through_serve::serve(home).await? else {
            return Ok(Routed::OwnBind);
        };
        let service: Service = reach::SPEED_SERVICE.parse()?;
        let dial = Dial {
            machine,
            service: &service,
            slip,
            reach: &self.reach,
            contacts,
        };
        // Isolated, as by own bind, and observed: the rate and the path it prints belong to this run's
        // own connection, and the path is read there, through `serve`, after the run.
        let socket = Rc::new(socket);
        let (session, observer) = match dial.observed(&socket, connected, OpenLane::Isolated).await
        {
            Ok(opened) => opened,
            Err(unattached) => {
                return Ok(Routed::Ran(Err(dial
                    .unattached(unattached, &*socket)
                    .await)));
            }
        };
        let (mode, label) = (self.mode(), machine.label());
        println!("{}", title(&label, mode));
        let ended = observed(
            mode,
            self.limit(),
            &session,
            observer,
            &label,
            async |own| dial.cut_or(&socket, own).await,
            &mut io::stdout(),
            &mut io::stderr(),
        )
        .await;
        Ok(Routed::Ran(ended))
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

/// The transfer over `session`, one stream through `serve`, beside `observer`, printing on `out` and
/// `err`. A measured run is Finished and then prints its path row and totals; a failed run prints its
/// error first and is Finished after. `cut` turns a broken run's own line into the one it prints, asking
/// `serve` whether it stopped.
#[expect(
    clippy::too_many_arguments,
    reason = "the run, its observer and the lines it prints to"
)]
async fn observed<P: PathSource, S: Session>(
    mode: Mode,
    limit: Limit,
    session: &S,
    mut observer: Observer<P>,
    label: &str,
    cut: impl AsyncFnOnce(eyre::Report) -> eyre::Report,
    out: &mut impl Write,
    err: &mut impl Write,
) -> eyre::Result<()> {
    let report = match transfer(mode, limit, session, observer.watch()).await {
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

/// Print the path row of a run through `serve` from its final observation, the Finish's, to `out`. When
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
