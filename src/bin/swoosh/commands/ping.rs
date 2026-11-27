//! `swoosh ping <machine>`: reach one machine by name or key and report round-trip time, `ping(8)` shaped.
//!
//! One machine, always: `alice/macbook` pings that one, and a bare person pings their one saved machine
//! (several refuse before anything binds). The block names the machine, then its `path:` (`direct` or
//! `relayed through <relay>`, the same words `status` prints) so a slow RTT reads as "it relayed", not a
//! mystery, then the `ping(8)` counts/loss and RTT distribution. No line names the transport: through
//! `serve` the verb does not know which one carried the run, and one line has one shape on both paths.
//!
//! With `-v`, it prints a line per probe as each one lands (like `tailscale ping`), and a `path:` line for
//! the path in force when the probes start and again each time it moves, so you WATCH a relayed link
//! hole-punch to direct. By own bind the moves come from the session's own stream of path changes, at the
//! moment the transport selects another; through `serve` from the samples its observer takes each second,
//! so a move may land a probe late. The `ping(8)` summary still follows the live lines.
//!
//! The run is one stream on Main, the session the rest of this home's traffic rides to the machine, and
//! every probe rides it: by own bind on the run's held session, read from that session after the run;
//! while `swoosh serve` runs here, one observed Open through it, its `path:` read by a Finish after the run.

use core::cell::RefCell;
use core::time::Duration;
use std::io::{self, Write};

use bifrost::{Path, Session};
use clap::Args;
use measure::{Ping, PingReport, Probe, ProtocolError, Refusal};
use nauthy::Service;
use swoosh::escape::{Escaped, causes};
use swoosh::learn::Admitted;
use swoosh::observation::Follow;
use swoosh::peer::{Machine, Peer};
use swoosh::peers::Hints;
use swoosh::reach;
use swoosh::serve::control_codec::{OpenLane, OpenRefusal, PeerRefusal};
use swoosh::streams::{Ask, Observing, StreamSource, Unopened};
use swoosh::transport::{self, ReachArgs};

use crate::commands::route::Route;
use crate::commands::{machine, through_serve};
use crate::screen::Paint;

/// Measure the round-trip time to a peer, addressed by a petname or their public key.
#[derive(Debug, Args)]
pub struct PingCmd {
    #[arg(value_name = "machine", help = machine::HELP)]
    pub peer: Peer,
    /// How many probes to send
    #[arg(short = 'c', long, value_name = "n", default_value_t = 4)]
    pub count: u32,
    /// Seconds between probes
    #[arg(short = 'i', long, value_name = "s", default_value_t = 1.0)]
    pub interval: f64,
    /// Print a line per probe, and one when the path changes
    #[arg(short = 'v', long)]
    pub verbose: bool,
    #[command(flatten)]
    pub reach: ReachArgs,
}

impl swoosh::reaching::Reaching for PingCmd {
    fn reach_args(&self) -> &transport::ReachArgs {
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
    /// `ping` reaches the peer's family-gated `ping` service, so it presents the member badge rooted at
    /// the dialing key. Stating `Family` FUSES the identity to `PersistedIfPresent`, so the self-badge
    /// roots correctly. A link typed as the peer is threaded INTO the credential so the ONE resolver
    /// ([`resolve`](swoosh::reaching::resolve)) owns both slots: slot 1 (link-or-badge) and the
    /// privacy-aware slot 2 (a fleet badge, only for a signet-bound slip).
    ///
    /// An `anyone` link typed as the peer presents alone, under a throwaway key (`Credential::dialing`).
    fn bind_role(&self) -> swoosh::reaching::BindRole {
        swoosh::reaching::BindRole::Dialing(self.credential())
    }
}

impl PingCmd {
    /// What this run dials as: the one value that picks its bind and what its stream presents.
    pub(crate) fn credential(&self) -> swoosh::credential::Credential {
        swoosh::credential::Credential::dialing(&self.peer, reach::PING_SERVICE)
    }

    /// Probe `machine` over one stream from `source` on Main, printing on `out` and `err`, as `route`
    /// words what it meets: its path and RTT summary, or the line for how far it got, and only an
    /// answered probe exits green. A machine that refuses the probe `NotAdmitted` prints the refusal as
    /// the error, after one of your devices is asked why through `source`. Once the stream is admitted,
    /// `admitted` gets its question, asked through `source`.
    ///
    /// # Errors
    ///
    /// The run's line: unreached, a refusal, a broken probe, or `serve` gone.
    pub async fn probe<'s, S: Observing + Copy + 's>(
        &self,
        source: S,
        route: &Route<'_>,
        machine: &Machine,
        admitted: Admitted<'s>,
        out: &mut impl Write,
        err: &mut impl Paint,
    ) -> eyre::Result<()> {
        // Main: the held session the rest of this home's traffic rides to the machine, so the round trip
        // and the path are the ones that traffic gets.
        let ask = Ask {
            peer: machine.key(),
            hints: Hints::NONE,
            service: reach::PING_SERVICE.parse()?,
            lane: OpenLane::Main,
            slip: self.peer.self_present(),
        };
        let (session, follow) = match source.observed(&ask).await {
            Ok(observed) => observed,
            Err(unopened) => {
                return self.unopened(unopened, source, route, machine, out).await;
            }
        };
        admitted.asked_through(source, machine.key());
        let stopped = async || route.stopped().await;
        self.observed(&session, follow, machine, stopped, out, err)
            .await
    }

    /// The line an open that gave no stream prints, and the run's exit: the same words on both paths,
    /// except where `route` words the outcome its own way.
    async fn unopened(
        &self,
        unopened: Unopened,
        source: impl StreamSource,
        route: &Route<'_>,
        machine: &Machine,
        out: &mut impl Write,
    ) -> eyre::Result<()> {
        let label = machine.label();
        let (line, outcome) = match unopened {
            unreached if unreached.unreached() => {
                tracing::debug!(?unreached, "the probe did not reach the machine");
                (format!("{label}: unreachable"), reach::Outcome::Unreachable)
            }
            // The machine refused this machine the service: the refusal, on stderr, once. One of your
            // devices is asked why first, through the same source.
            Unopened::Refused(OpenRefusal::Peer(PeerRefusal::NotAdmitted)) => {
                let service: Service = reach::PING_SERVICE.parse()?;
                let slip = self.peer.self_present();
                let diagnosis = reach::diagnose_through(&source, machine, &service, slip).await;
                return Err(machine::refused(machine, &service, diagnosis));
            }
            // The machine was REACHED but refused this probe some other way: a distinct line that says
            // so, not a healthy machine with 100% loss, and NOT "unreachable".
            Unopened::Refused(OpenRefusal::Peer(refusal)) => {
                let refusal = Refusal::Stream(bifrost::Refusal::from(refusal));
                (refused_line(&label, &refusal), reach::Outcome::Refused)
            }
            Unopened::Refused(
                OpenRefusal::Broken(detail) | OpenRefusal::PeerUnreadable(detail),
            ) => (
                failed_cause_line(&label, &detail.to_string()),
                reach::Outcome::Failed,
            ),
            other => return Err(route.line(other, machine).await),
        };
        writeln!(out, "{line}")?;
        route.result(outcome, machine)
    }

    /// The probes over `session`, one stream, beside `follow`, printing on `out` and `err`. A measured
    /// run is finished and then printed, its `path:` the final reading's; a failed run prints its line
    /// and its error first, and is finished after. Before a broken run blames the machine, `stopped`
    /// asks whether `serve` itself went: then its line stands alone, with nothing on stdout. A run that
    /// opened its stream reached the machine, so its exit names no bind.
    async fn observed<S: Session>(
        &self,
        session: &S,
        mut follow: impl Follow,
        machine: &Machine,
        stopped: impl AsyncFnOnce() -> Option<eyre::Report>,
        out: &mut impl Write,
        err: &mut impl Paint,
    ) -> eyre::Result<()> {
        let label = machine.label();
        let report = if self.verbose {
            // Both live callbacks print, one per probe and one per move, so they share the writer.
            let live = RefCell::new(&mut *out);
            let mut shown = follow.latest().path;
            let written = writeln!(live.borrow_mut(), "{}", path_line(&label, &shown));
            if let Err(error) = written {
                return Err(through_serve::failed(error.into(), follow, err).await);
            }
            // A live row that cannot be written is dropped: the block after the run, which carries the
            // result, reports the failed write.
            let probes = self.plan().observing(session, |probe| {
                let _ = writeln!(live.borrow_mut(), "{}", probe_line(&label, probe));
            });
            let moves = follow.moves(|info| {
                if info.path != shown {
                    shown = info.path.clone();
                    let _ = writeln!(live.borrow_mut(), "{}", path_line(&label, &shown));
                }
            });
            tokio::select! {
                // Biased, so a move that landed prints before the probe line that follows it.
                biased;
                never = moves => match never {},
                report = probes => report,
            }
        } else {
            tokio::select! {
                report = self.plan().run(session) => report,
                never = follow.moves(|_| {}) => match never {},
            }
        };
        let (line, outcome) = match report {
            Ok(report) => {
                let observed = follow.finish().await;
                // A cut folds into loss rather than an error, and then the Finish fails too: ask whether
                // `serve` went before warning about a path, since its stop is the run's real end.
                if observed.last.is_err()
                    && report.loss() > 0.0
                    && let Some(gone) = stopped().await
                {
                    through_serve::log_path(observed);
                    print_block(out, &label, || Ok(None), &report)?;
                    return Err(gone);
                }
                // The warning for a path that could not be read lands where its row would have.
                let path = || Ok(through_serve::final_path(observed, err)?.map(|info| info.path));
                print_block(out, &label, path, &report)?;
                return Ok(());
            }
            Err(ProtocolError::Refused(refusal)) => {
                (refused_line(&label, &refusal), reach::Outcome::Refused)
            }
            // A broken run asks whether `serve` went first: then the machine is not to blame. The full
            // cause chain is rendered because the outer half of a stream failure is routinely the
            // useless half.
            Err(error) => match stopped().await {
                Some(gone) => return Err(through_serve::failed(gone, follow, err).await),
                None => (failed_line(&label, &error), reach::Outcome::Failed),
            },
        };
        // A line that cannot be written ends the run as a failure, finished all the same.
        if let Err(error) = writeln!(out, "{line}") {
            return Err(through_serve::failed(error.into(), follow, err).await);
        }
        through_serve::ended(outcome.unbound_result(&label), follow, err).await
    }

    /// The probes this run sends.
    fn plan(&self) -> Ping {
        Ping {
            count: self.count,
            interval: Duration::from_secs_f64(self.interval),
        }
    }
}

/// Print one machine's block on `out`: the machine, its `path:` row when `path` reads one, then the
/// `ping(8)` counts and RTT distribution indented beneath it. `path` is read after the machine's line,
/// so whatever it says about a path it could not read lands where the row would have.
fn print_block(
    out: &mut impl Write,
    label: &str,
    path: impl FnOnce() -> io::Result<Option<Path>>,
    report: &PingReport,
) -> io::Result<()> {
    writeln!(out, "{label}")?;
    if let Some(path) = path()? {
        writeln!(out, "  path: {}", reach::PathLine(&path))?;
    }
    let loss_pct = report.loss() * 100.0;
    writeln!(
        out,
        "  {} sent, {} received, {loss_pct:.0}% loss",
        report.sent(),
        report.received()
    )?;
    if let (Some(min), Some(avg), Some(max), Some(mdev)) =
        (report.min(), report.avg(), report.max(), report.mdev())
    {
        writeln!(
            out,
            "  rtt min/avg/max/mdev = {:.3}/{:.3}/{:.3}/{:.3} ms",
            millis(min),
            millis(avg),
            millis(max),
            millis(mdev),
        )?;
    }
    Ok(())
}

/// One path line: `<label>, path: <path>`, printed under `-v` for the path in force and for each change.
fn path_line(label: &str, path: &Path) -> String {
    format!("{label}, path: {}", reach::PathLine(path))
}

/// One live probe line: `<label>, seq <n> rtt <x> ms` (or `... lost` for a dropped reply), `tailscale
/// ping` shaped. The path is not sampled here: it has its own line when it changes.
fn probe_line(label: &str, probe: Probe) -> String {
    match probe.rtt {
        Some(rtt) => format!("{label}, seq {} rtt {:.3} ms", probe.seq, millis(rtt)),
        None => format!("{label}, seq {} lost", probe.seq),
    }
}

/// A duration as fractional milliseconds, the unit ping reports.
fn millis(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

/// The line for a device that was reached and refused the probe. The refusal's detail is the peer's
/// text, so it prints through the escaper.
fn refused_line(label: &str, refusal: &Refusal) -> String {
    format!(
        "{label}: reached, but refused ({})",
        Escaped(&refusal.to_string())
    )
}

/// The line for a device that was reached and whose exchange then broke.
///
/// Says it was REACHED, so it is never confused with `unreachable`, and names the cause rather than a
/// round-trip time, because a broken exchange measured nothing.
fn failed_line(label: &str, error: &ProtocolError) -> String {
    failed_cause_line(label, &causes(error))
}

/// [`failed_line`] for a cause already rendered. The cause can carry the peer's text, so it prints
/// through the escaper.
fn failed_cause_line(label: &str, cause: &str) -> String {
    format!(
        "{label}: reached, but the probe failed ({})",
        Escaped(cause)
    )
}

#[cfg(test)]
mod tests {
    use bifrost::{PathChanges, Relay};

    use super::*;

    /// `ping` to one of your devices that refuses it prints the dial refusal once, as the error, after
    /// asking the device why through the same run's source; nothing reaches stdout.
    #[tokio::test]
    async fn a_refused_ping_to_your_device_names_the_cause() {
        use swoosh::testkit::{Script, ScriptedPeer};

        use crate::commands::through_serve::tests::Dialing;

        let key = bifrost::NodeId::from_ed25519_secret(&[0x67; 32]);
        let mut contacts = swoosh::contacts::Contacts::default();
        contacts
            .save(&"me/nas".parse().expect("a device"), key)
            .expect("the name is free");
        let cmd = Dialing::of(&["ping", "me/nas"]);
        let machine = crate::commands::through_serve::tests::machine(&contacts, "me/nas");
        let peer = ScriptedPeer::new(
            key,
            [
                Script::Refuse(bifrost::Refusal::NotAdmitted),
                Script::Lists(vec!["ping"]),
            ],
        );
        let node = bifrost::Node::new(peer.clone(), bifrost::NoDiscovery);
        let peers = swoosh::peers::Peers::new(&node);
        let home = crate::commands::through_serve::tests::empty_home("ping-refused");
        let ran = cmd
            .by_own_bind(&peers, &home, node.node_id(), &machine)
            .await;
        assert!(ran.out.is_empty(), "{}", ran.out);
        let error = ran.ended.expect_err("a refused ping exits non-zero");
        assert_eq!(
            format!("{error:#}"),
            "me/nas refused ping\n  ping was turned off or removed on nas, or nas is too busy to take it \
             now.\n  On nas, run this to see which:\n    swoosh status"
        );
        let asked: Vec<String> = peer
            .requests()
            .into_iter()
            .map(|request| request.service)
            .collect();
        assert_eq!(asked, ["ping", "control.serve"]);
    }

    /// A machine that echoes every probe at once, on the one stream it hands out, or fails that stream
    /// with `refused`, or, `silent`, takes the probes and answers none.
    #[derive(Default)]
    struct Echo {
        refused: Option<bifrost::Error>,
        silent: bool,
    }

    impl Echo {
        fn refusing(refusal: bifrost::Refusal) -> Self {
            Self {
                refused: Some(bifrost::Error::Refused(refusal)),
                ..Self::default()
            }
        }
    }

    impl Session for Echo {
        type Write = swoosh::testkit::TestWrite<tokio::io::WriteHalf<tokio::io::DuplexStream>>;
        type Read = tokio::io::ReadHalf<tokio::io::DuplexStream>;

        fn peer(&self) -> bifrost::NodeId {
            bifrost::NodeId::from_ed25519_secret(&[0x67; 32])
        }

        async fn open_bi(&self) -> Result<(Self::Write, Self::Read), bifrost::Error> {
            use measure::protocol::{Request, Response};

            match &self.refused {
                Some(bifrost::Error::Refused(refusal)) => {
                    return Err(bifrost::Error::Refused(refusal.clone()));
                }
                Some(_) => return Err(bifrost::Error::Stream("the stream was cut".into())),
                None => {}
            }
            let (here, there) = tokio::io::duplex(4096);
            let silent = self.silent;
            tokio::spawn(async move {
                if silent {
                    // Hold the far end and read nothing: every probe is lost to its bound.
                    let _held = there;
                    return core::future::pending().await;
                }
                let (mut read, mut write) = tokio::io::split(there);
                while let Ok(Request::Ping {
                    seq,
                    sent_unix_nanos,
                }) = Request::read(&mut read).await
                {
                    let pong = Response::Pong {
                        seq,
                        sent_unix_nanos,
                    };
                    if pong.write(&mut write).await.is_err() {
                        break;
                    }
                }
            });
            let (read, write) = tokio::io::split(here);
            Ok((write.into(), read))
        }

        async fn accept_bi(&self) -> Result<(Self::Write, Self::Read), bifrost::Error> {
            Err(bifrost::Error::Closed)
        }

        async fn wait_closed(&self) {
            core::future::pending().await
        }

        fn close(&self) {}

        fn path_changes(&self) -> PathChanges {
            PathChanges::fixed(Path::Unknown)
        }
    }

    /// `ping <argv>` to `me/nas` through `serve`, over `session`, the Open having attached on a relayed
    /// path and the resident answering the queries with `replies`, `serve` still answering after the
    /// run: what it printed on stdout, what it did in order (stderr lines and queries), and how it ended.
    async fn through_serve(
        argv: &[&str],
        session: &Echo,
        replies: impl IntoIterator<Item = swoosh::serve::control_codec::PathReply>,
    ) -> (String, Vec<String>, eyre::Result<()>) {
        through_serve_with(argv, session, replies, None).await.0
    }

    /// [`through_serve`] with `gone` the line `serve` stops with when asked after the run, or `None`
    /// while it answers, and whether it was asked.
    async fn through_serve_with(
        argv: &[&str],
        session: &Echo,
        replies: impl IntoIterator<Item = swoosh::serve::control_codec::PathReply>,
        gone: Option<&str>,
    ) -> ((String, Vec<String>, eyre::Result<()>), bool) {
        let events = crate::commands::through_serve::tests::Events::answering(replies);
        let mut out = Vec::new();
        let (ended, asked) = run_through_serve(argv, session, &events, gone, &mut out).await;
        (
            (String::from_utf8(out).expect("text"), events.log(), ended),
            asked,
        )
    }

    /// `ping <argv>` to `me/nas` through `serve`, over `session`, the resident and stderr being `events`
    /// and stdout `out`: how it ended, and whether `serve` was asked if it went.
    async fn run_through_serve(
        argv: &[&str],
        session: &Echo,
        events: &crate::commands::through_serve::tests::Events,
        gone: Option<&str>,
        out: &mut impl Write,
    ) -> (eyre::Result<()>, bool) {
        use clap::Parser as _;

        use crate::commands::through_serve::tests::{reading, relayed};

        #[derive(clap::Parser)]
        struct Wrap {
            #[command(flatten)]
            ping: PingCmd,
        }

        let mut contacts = swoosh::contacts::Contacts::default();
        contacts
            .save(&"me/nas".parse().expect("a device"), session.peer())
            .expect("the name is free");
        let cmd = Wrap::try_parse_from(["x", "me/nas"].iter().chain(argv))
            .expect("ping parses")
            .ping;
        let machine = cmd.peer.machine(&contacts).expect("one machine");
        let asked = core::cell::Cell::new(false);
        // On the paused clock, and past measure's own bound on an unanswered probe.
        let ended = tokio::time::timeout(
            Duration::from_secs(60),
            cmd.observed(
                session,
                events.observer(reading(relayed())).await,
                &machine,
                async || {
                    asked.set(true);
                    gone.map(|line| eyre::eyre!("{line}"))
                },
                out,
                &mut events.clone(),
            ),
        )
        .await
        .expect("the run ends");
        (ended, asked.get())
    }

    /// A line that cannot be written to stdout ends the run as a failure, its error printed and its
    /// receipt Finished all the same: the `-v` row before the probes, and the refusal's line after them.
    #[tokio::test(start_paused = true)]
    async fn an_unwritable_stdout_still_finishes_the_run() {
        use crate::commands::through_serve::Reported;
        use crate::commands::through_serve::tests::{Events, Unwritable};

        let busy = bifrost::Refusal::Unavailable {
            detail: bifrost::RefusalDetail::bounded("busy"),
        };
        for (argv, session) in [
            (&["-v", "-c", "1"][..], Echo::default()),
            (&["-c", "1"][..], Echo::refusing(busy)),
        ] {
            let events = Events::default();
            let (ended, _) =
                run_through_serve(argv, &session, &events, None, &mut Unwritable).await;
            assert!(ended.expect_err("exit 1").is::<Reported>(), "{argv:?}");
            assert_eq!(
                events.log(),
                ["stderr: error: broken pipe", "Finish"],
                "{argv:?}"
            );
        }
    }

    /// A path that could not be read warns where its row would have printed, inside the block, as
    /// `speed` does.
    #[tokio::test(start_paused = true)]
    async fn the_path_warning_lands_where_the_row_would_have() {
        use crate::commands::through_serve::tests::Events;

        let events = Events::default();
        let (ended, _) = run_through_serve(
            &["-c", "1"],
            &Echo::default(),
            &events,
            None,
            &mut events.stdout(),
        )
        .await;
        ended.expect("the run measured");
        assert_eq!(
            events.log()[..4],
            [
                "Finish",
                "stdout: me/nas",
                "stderr: warning: could not read the path of this run",
                "stdout:   1 sent, 1 received, 0% loss",
            ]
        );
    }

    /// Through `serve` the block's `path:` is the Finish's, read after the run, never the path the
    /// stream attached on; a run shorter than the spacing is Finished as it ends.
    #[tokio::test(start_paused = true)]
    async fn ping_through_serve_prints_the_finishs_path() {
        use swoosh::serve::control_codec::PathReply;

        let (out, log, ended) = through_serve(
            &["-c", "1"],
            &Echo::default(),
            [PathReply::Sample(bifrost::ConnInfo {
                path: Path::Direct,
                ..bifrost::ConnInfo::default()
            })],
        )
        .await;
        ended.expect("an answered ping exits green");
        assert!(
            out.starts_with("me/nas\n  path: direct\n  1 sent, 1 received, 0% loss\n"),
            "{out}"
        );
        assert_eq!(log, ["Finish"]);
    }

    /// When the reading after the run fails, the block has no `path:` row, stderr warns once, and the
    /// exit stays the run's.
    #[tokio::test(start_paused = true)]
    async fn ping_through_serve_without_a_final_path_warns_and_keeps_its_exit() {
        let (out, log, ended) = through_serve(&["-c", "1"], &Echo::default(), []).await;
        ended.expect("the run measured; the missing path does not fail it");
        assert!(
            out.starts_with("me/nas\n  1 sent, 1 received, 0% loss\n"),
            "{out}"
        );
        assert_eq!(
            log,
            [
                "Finish",
                "stderr: warning: could not read the path of this run"
            ]
        );
    }

    /// `ping -v` through `serve` prints the path the stream attached on first, then a row only when a
    /// sample reads another path: a sample on the same path prints nothing, and so does a failed one.
    #[tokio::test(start_paused = true)]
    async fn ping_v_through_serve_prints_a_row_when_a_sample_moves() {
        use swoosh::serve::control_codec::PathReply;

        let direct = bifrost::ConnInfo {
            path: Path::Direct,
            ..bifrost::ConnInfo::default()
        };
        let relayed = crate::commands::through_serve::tests::reading(
            crate::commands::through_serve::tests::relayed(),
        );
        // Probes at 0, 1.25, 2.5 and 3.75 s; samples at 1, 2 and 3 s, then the Finish.
        let (out, log, ended) = through_serve(
            &["-v", "-c", "4", "-i", "1.25"],
            &Echo::default(),
            [
                PathReply::Sample(relayed),
                PathReply::Sample(direct.clone()),
                PathReply::Unavailable,
                PathReply::Sample(direct),
            ],
        )
        .await;
        ended.expect("an answered ping exits green");
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(
            lines[..7],
            [
                "me/nas, path: relayed through relay.example",
                "me/nas, seq 0 rtt 0.000 ms",
                "me/nas, seq 1 rtt 0.000 ms",
                "me/nas, path: direct",
                "me/nas, seq 2 rtt 0.000 ms",
                "me/nas, seq 3 rtt 0.000 ms",
                "me/nas",
            ],
            "{out}"
        );
        assert_eq!(lines[7], "  path: direct", "{out}");
        assert_eq!(log, ["Sample", "Sample", "Sample", "Finish"]);
    }

    /// A ping through `serve` that is refused prints its line and its error first, and Finishes its
    /// receipt after, in the run's own task.
    #[tokio::test(start_paused = true)]
    async fn a_failed_ping_through_serve_prints_its_error_then_finishes() {
        let busy = bifrost::Refusal::Unavailable {
            detail: bifrost::RefusalDetail::bounded("busy"),
        };
        for (refused, line, error) in [(
            busy,
            "me/nas: reached, but refused (unavailable: busy)\n",
            "stderr: error: me/nas: reached, but refused",
        )] {
            let ((out, log, ended), asked) =
                through_serve_with(&["-c", "1"], &Echo::refusing(refused), [], Some("gone")).await;
            assert!(!asked, "a refusal proves serve relayed an answer");
            assert!(
                ended
                    .expect_err("a refused ping exits non-zero")
                    .is::<crate::commands::through_serve::Reported>()
            );
            assert_eq!(out, line);
            assert_eq!(log, [error, "Finish"]);
        }
    }

    /// A refusal through `serve` names the machine as every other line does, by its name here, not as it
    /// was typed: a bare person reads as the one machine of theirs that was dialed.
    #[tokio::test(start_paused = true)]
    async fn a_refusal_through_serve_names_the_machine_not_the_word_typed() {
        use clap::Parser as _;

        use crate::commands::through_serve::tests::{Events, reading, relayed};

        #[derive(clap::Parser)]
        struct Wrap {
            #[command(flatten)]
            ping: PingCmd,
        }

        let session = Echo::refusing(bifrost::Refusal::Unavailable {
            detail: bifrost::RefusalDetail::bounded("busy"),
        });
        let mut contacts = swoosh::contacts::Contacts::default();
        contacts
            .save(&"alice/laptop".parse().expect("a contact"), session.peer())
            .expect("the name is free");
        let cmd = Wrap::try_parse_from(["x", "alice", "-c", "1"])
            .expect("ping parses")
            .ping;
        let machine = cmd.peer.machine(&contacts).expect("one machine");
        let events = Events::answering([]);
        let mut out = Vec::new();
        let ended = tokio::time::timeout(
            Duration::from_secs(60),
            cmd.observed(
                &session,
                events.observer(reading(relayed())).await,
                &machine,
                async || None,
                &mut out,
                &mut events.clone(),
            ),
        )
        .await
        .expect("the run ends");
        assert!(ended.is_err(), "a refused ping exits non-zero");
        assert_eq!(
            String::from_utf8(out).expect("text"),
            "alice/laptop: reached, but refused (unavailable: busy)\n"
        );
        assert_eq!(
            events.log(),
            [
                "stderr: error: alice/laptop: reached, but refused",
                "Finish"
            ]
        );
    }

    /// A run that broke through `serve` asks whether `serve` went before blaming the machine: gone, its
    /// line stands alone with nothing on stdout; still answering, the probe-failed line and its error.
    #[tokio::test(start_paused = true)]
    async fn a_broken_ping_through_serve_asks_whether_serve_went() {
        let cut = Echo {
            refused: Some(bifrost::Error::Closed),
            ..Echo::default()
        };
        let ((out, log, ended), asked) =
            through_serve_with(&["-c", "1"], &cut, [], Some("serve stopped")).await;
        assert!(asked);
        assert!(
            ended
                .expect_err("exit 1")
                .is::<crate::commands::through_serve::Reported>()
        );
        assert_eq!(out, "");
        assert_eq!(log, ["stderr: error: serve stopped", "Finish"]);

        let ((out, log, ended), asked) = through_serve_with(&["-c", "1"], &cut, [], None).await;
        assert!(asked);
        assert!(ended.is_err());
        assert_eq!(
            out,
            "me/nas: reached, but the probe failed (stream: the stream was cut)\n"
        );
        assert_eq!(
            log,
            [
                "stderr: error: me/nas: reached, but the probe failed",
                "Finish"
            ]
        );
    }

    /// A cut that folds into loss leaves a measured block and a failed Finish: `serve` is asked then,
    /// and when it went its line replaces the path warning, exit 1. While it answers, the warning.
    #[tokio::test(start_paused = true)]
    async fn a_lossy_ping_whose_finish_failed_asks_whether_serve_went() {
        let silent = Echo {
            silent: true,
            ..Echo::default()
        };
        let ((out, log, ended), asked) =
            through_serve_with(&["-c", "1"], &silent, [], Some("serve stopped")).await;
        assert!(asked);
        assert_eq!(format!("{:#}", ended.expect_err("exit 1")), "serve stopped");
        assert_eq!(out, "me/nas\n  1 sent, 0 received, 100% loss\n");
        assert_eq!(log, ["Sample", "Finish"]);

        let ((out, log, ended), _) = through_serve_with(&["-c", "1"], &silent, [], None).await;
        ended.expect("a measured run keeps its exit");
        assert_eq!(out, "me/nas\n  1 sent, 0 received, 100% loss\n");
        assert_eq!(
            log,
            [
                "Sample",
                "Finish",
                "stderr: warning: could not read the path of this run"
            ]
        );
    }

    /// `ping`'s part of the no-transport rule, on both paths: the block's head is the machine alone and
    /// a `path:` row follows it, and nothing printed, the error included, names the transport. A run
    /// through `serve` that measured ends with no error, so the error's part is read off one that broke,
    /// whose line and error print on stdout and stderr.
    #[tokio::test(start_paused = true)]
    async fn default_output_names_no_transport() {
        use swoosh::serve::control_codec::PathReply;
        use swoosh::testkit::{Script, ScriptedPeer};

        use crate::commands::through_serve::tests::{Dialing, empty_home, machine};

        let (out, log, ended) = through_serve(
            &["-c", "1"],
            &Echo::default(),
            [PathReply::Sample(bifrost::ConnInfo {
                path: Path::Direct,
                ..bifrost::ConnInfo::default()
            })],
        )
        .await;
        ended.expect("a measured ping through serve exits 0");
        let serve = (out, log.join("\n"), Ok(()));
        // Through `serve`, a ping whose stream was cut prints its line and its error, exit 1.
        let cut = Echo {
            refused: Some(bifrost::Error::Closed),
            ..Echo::default()
        };
        let ((out, log, ended), _) = through_serve_with(&["-c", "1"], &cut, [], None).await;
        assert!(ended.is_err(), "a broken ping exits 1");
        assert_eq!(
            out,
            "me/nas: reached, but the probe failed (stream: the stream was cut)\n"
        );
        assert_eq!(
            log,
            [
                "stderr: error: me/nas: reached, but the probe failed",
                "Finish"
            ]
        );
        for printed in [&out, &log.join("\n")] {
            for word in ["via", "iroh", "transport"] {
                assert!(!printed.contains(word), "broken: {word}: {printed}");
            }
        }
        // By own bind, over a machine that holds the stream and answers no probe: the block still prints.
        let key = Echo::default().peer();
        let mut contacts = swoosh::contacts::Contacts::default();
        contacts
            .save(&"me/nas".parse().expect("a device"), key)
            .expect("the name is free");
        let peer = ScriptedPeer::new(key, [Script::Holds]);
        let node = bifrost::Node::new(peer, bifrost::NoDiscovery);
        let peers = swoosh::peers::Peers::new(&node);
        let home = empty_home("ping-no-transport");
        let ran = Dialing::of(&["ping", "me/nas", "-c", "1"])
            .by_own_bind(&peers, &home, node.node_id(), &machine(&contacts, "me/nas"))
            .await;
        let own = (ran.out, ran.err, ran.ended);
        for (path, (out, err, ended)) in [("serve", serve), ("own", own)] {
            let error = ended
                .err()
                .map(|error| format!("{error:#}"))
                .unwrap_or_default();
            let mut lines = out.lines();
            assert_eq!(lines.next(), Some("me/nas"), "{path}: {out}");
            assert!(
                lines.next().is_some_and(|row| row.starts_with("  path: ")),
                "{path}: {out}"
            );
            for printed in [&out, &err, &error] {
                for word in ["via", "iroh", "transport"] {
                    assert!(!printed.contains(word), "{path}: {word}: {printed}");
                }
            }
        }
    }

    /// A relayed path through `host`, as iroh names one: by the relay's URL.
    fn relayed(host: &str) -> Path {
        Path::Relayed(Relay::from(
            url::Url::parse(&format!("https://{host}/")).expect("a relay url"),
        ))
    }

    /// A device that answered the dial and then broke gets a LINE, not the end of the run. It used to
    /// abort the whole fan-out with its error, so every device after it went untried and the operator
    /// learned nothing about them, while `status` reported all of them. The line says the node was
    /// reached, renders the cause chain rather than a round-trip time (a broken exchange measured
    /// nothing), and folds to an outcome that is not healthy.
    ///
    /// What this cannot assert is the control flow itself: the loop has no seam a unit test can drive.
    /// It pins the rendering and the rank; the continuing is structural, in the arm no longer returning.
    #[test]
    fn a_broken_device_gets_a_line_and_the_run_keeps_its_verdict() {
        let error = ProtocolError::from(bifrost::Error::Stream("peer went away".into()));
        let line = failed_line("alice/nas", &error);

        assert!(
            line.starts_with("alice/nas: reached, but the probe failed ("),
            "the line names the device and says it was reached: {line}"
        );
        assert!(
            line.contains("peer went away"),
            "the cause chain is rendered, not just its useless outer half: {line}"
        );
        assert!(
            !line.contains("rtt"),
            "a broken exchange measured nothing, so no time is reported: {line}"
        );
        assert_ne!(
            reach::Outcome::default().max(reach::Outcome::Failed),
            reach::Outcome::Healthy,
            "one broken device must not leave the run's verdict green"
        );
    }

    /// A path is named by the one carrying bytes: `direct`, `relayed through <host>` with the relay's
    /// host and nothing else of its URL, or `unknown`. A direct path with a standby relay is `Direct`
    /// (bifrost's), so it reads `direct`. iroh's default relays are named with a root dot, which is dropped
    /// so the line does not end in what reads as a period.
    #[test]
    fn a_path_is_direct_or_relayed_through_its_relay() {
        for (path, said) in [
            (Path::Direct, "path: direct"),
            (
                relayed("euw1-1.relay.iroh.network"),
                "path: relayed through euw1-1.relay.iroh.network",
            ),
            (
                relayed("euc1-1.relay.n0.iroh.link."),
                "path: relayed through euc1-1.relay.n0.iroh.link",
            ),
            (Path::Unknown, "path: unknown"),
        ] {
            let line = path_line("alice/macbook", &path);
            assert!(line.ends_with(said), "{path:?} reads {said}: {line}");
        }
    }

    #[test]
    fn a_lost_probe_reports_lost_not_a_zero_rtt() {
        let line = probe_line("alice/macbook", Probe { seq: 0, rtt: None });
        assert_eq!(line, "alice/macbook, seq 0 lost");
    }

    /// A peer's refusal detail holding a carriage return, an ESC CSI sequence and a bidi override prints
    /// as escapes on one line, so a node that refused cannot redraw its line as a healthy probe.
    #[test]
    fn a_hostile_refusal_prints_escaped() {
        let refusal = Refusal::Stream(bifrost::Refusal::Unavailable {
            detail: bifrost::RefusalDetail::bounded(
                "no\r\u{1b}[2Kalice/macbook, path: direct, seq 0 rtt 0.4 ms\u{202e}",
            ),
        });
        let line = refused_line("alice/macbook", &refusal);
        assert_eq!(
            line,
            r"alice/macbook: reached, but refused (unavailable: no\r\u{1b}[2Kalice/macbook, path: direct, seq 0 rtt 0.4 ms\u{202e})"
        );
        assert!(
            !line.contains(['\r', '\n', '\u{1b}', '\u{202e}']),
            "no raw byte of the peer's reaches the line: {line:?}"
        );
    }
}
