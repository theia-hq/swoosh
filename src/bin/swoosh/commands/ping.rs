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
//! While `swoosh serve` runs here, the run is one observed Open through it on its held session to the
//! machine: every probe rides that one stream, and the block's `path:` is read by a Finish after the run.

use core::cell::RefCell;
use core::future::Future;
use core::time::Duration;
use std::io::{self, Write};
use std::rc::Rc;

use bifrost::{Discovery, Node, Path, PathChanges, Session, Transport};
use clap::Args;
use futures::StreamExt as _;
use measure::{Ping, PingReport, Probe, ProtocolError, Refusal};
use nauthy::{Link, Service};
use swoosh::contacts::Contacts;
use swoosh::escape::{Escaped, causes};
use swoosh::home::Home;
use swoosh::learn::Admitted;
use swoosh::observation::{Observer, PathSource};
use swoosh::peer::{Machine, Peer};
use swoosh::reach;
use swoosh::serve::control_codec::{OpenLane, OpenRefusal, PeerRefusal};
use swoosh::transport::{self, ReachArgs};

use crate::commands::machine;
use crate::commands::through_serve::{self, Dial, Routed, Unattached};

/// Measure the round-trip time to a peer, addressed by a petname or their public key.
#[derive(Debug, Args)]
pub struct PingCmd {
    #[arg(value_name = "machine", help = machine::HELP)]
    pub peer: Peer,
    /// how many probes to send
    #[arg(short = 'c', long, value_name = "n", default_value_t = 4)]
    pub count: u32,
    /// seconds between probes
    #[arg(short = 'i', long, value_name = "s", default_value_t = 1.0)]
    pub interval: f64,
    /// print a line per probe, and one when the path changes
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
        swoosh::reaching::BindRole::Dialing(swoosh::credential::Credential::dialing(
            &self.peer,
            reach::PING_SERVICE,
        ))
    }

    /// Uniform dispatch: unpack the reach context and run. `ping` reads the resolved machine, the
    /// `transport` label, and the resolved `present` badge.
    async fn run<'n: 'p, 'p, T: Transport, D: Discovery>(
        self,
        node: &'n Node<T, D>,
        ctx: swoosh::reaching::ReachCtx<'_>,
        _peers: &'p swoosh::peers::Peers<'n, T, D>,
    ) -> eyre::Result<()>
    where
        T::Session: 'static,
        <T::Session as Session>::Write: Send + 'static,
        <T::Session as Session>::Read: Send + 'static,
    {
        let Some(machine) = ctx.machine else {
            eyre::bail!("internal: `ping` ran without its machine resolved (root-dispatch bug)");
        };
        self.run_ping(
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

impl PingCmd {
    /// Dial the machine, probe it, and print its path and RTT summary. A machine that refuses the probe
    /// `NotAdmitted` prints the dial refusal on stderr instead (one of your devices is asked why); any
    /// other outcome prints its line, and only an answered probe exits green.
    async fn run_ping<T: Transport, D: Discovery>(
        self,
        node: &Node<T, D>,
        machine: &Machine,
        bound: &transport::Bound,
        present: Option<Link>,
        membership: Option<Link>,
        admitted: Admitted,
    ) -> eyre::Result<()>
    where
        T::Session: 'static,
    {
        // Slots 1 and 2 are ALREADY resolved by the composition root's ONE resolver: slot 1 (`present`) is
        // the link typed as the peer or the member badge, slot 2 (`membership`) is a fleet badge only for a
        // signet-bound slip. The verb never threads a slip itself, so it cannot desync the two.
        let plan = self.plan();
        let label = machine.label();
        let service: Service = reach::PING_SERVICE.parse()?;
        let session = match reach::dial_service(
            node,
            machine,
            &self.peer,
            &service,
            Option::clone(&present),
            Option::clone(&membership),
            bound,
        )
        .await
        {
            // Its first admitted probe stream tells the composition root it may ask which root vouches for
            // the machine.
            Ok((session, connector)) => admitted.watch(session, connector),
            Err(_error) => {
                println!("{label}: unreachable");
                return reach::Outcome::Unreachable.into_result(&self.peer, bound);
            }
        };
        // With `-v`, print a line per probe as it lands, and a path line for the path in force and each
        // change the session reports, so the moment a relayed link flips to direct is visible live. The
        // observer borrows the session read-only, alongside the run's own read-only borrow.
        let report = if self.verbose {
            let probes = plan.observing(&session, |probe| {
                println!("{}", probe_line(&label, probe));
            });
            watching(session.path_changes(), probes, |path| {
                println!("{}", path_line(&label, path));
            })
            .await
        } else {
            plan.run(&session).await
        };
        let outcome = match report {
            Ok(report) => {
                print_block(
                    &mut io::stdout(),
                    &label,
                    || Ok(Some(session.conn_info().path)),
                    &report,
                )?;
                reach::Outcome::Healthy
            }
            // The machine refused this machine the service: the dial refusal, on stderr, once. One of your
            // devices is asked why first, over a second connection, since the gated session opens nothing
            // but `ping`.
            Err(ProtocolError::Refused(Refusal::Stream(bifrost::Refusal::NotAdmitted))) => {
                let diagnosis =
                    reach::diagnose_over(node, machine, &service, present, membership).await;
                return Err(machine::refused(machine, &service, diagnosis));
            }
            // The node was REACHED but refused this probe some other way: a distinct line that says so (not
            // a healthy machine with 100% loss, and NOT "unreachable"), rendering the typed refusal so a
            // refusal reads descriptively and is never doubled (`refused (refused)`).
            Err(ProtocolError::Refused(refusal)) => {
                println!("{}", refused_line(&label, &refusal));
                reach::Outcome::Refused
            }
            // The node was REACHED and the exchange then broke. The full cause chain is rendered because
            // the outer half of a stream failure is routinely the useless half.
            Err(error) => {
                println!("{}", failed_line(&label, &error));
                reach::Outcome::Failed
            }
        };

        // The composition root closes the node once anything still running beside the verb has ended, so
        // the last frames land and iroh shuts down cleanly.
        outcome.into_result(&self.peer, bound)
    }
}

impl PingCmd {
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
        let service: Service = reach::PING_SERVICE.parse()?;
        let mut dial = Dial {
            machine,
            service: &service,
            slip,
            reach: &self.reach,
            contacts,
        };
        // Main: the held session the rest of this home's traffic through `serve` rides to the machine,
        // so the round trip and the path are the ones that traffic gets.
        let socket = Rc::new(socket);
        let (session, observer) = match dial.observed(&socket, connected, OpenLane::Main).await {
            Ok(opened) => opened,
            Err(Unattached::Refused(refusal)) => match own_line(&machine.label(), refusal) {
                Ok((line, outcome)) => {
                    writeln!(io::stdout(), "{line}")?;
                    return Ok(Routed::Ran(outcome.unbound_result(&self.peer)));
                }
                Err(refusal) => {
                    let report = dial
                        .unattached(Unattached::Refused(refusal), &*socket)
                        .await;
                    return Ok(Routed::Ran(Err(report)));
                }
            },
            Err(failed) => {
                return Ok(Routed::Ran(Err(dial.unattached(failed, &*socket).await)));
            }
        };
        let ended = self
            .observed(
                &session,
                observer,
                machine,
                async || dial.stopped(&socket).await,
                &mut io::stdout(),
                &mut io::stderr(),
            )
            .await;
        Ok(Routed::Ran(ended))
    }

    /// The probes over `session`, one stream through `serve`, beside `observer`, printing on `out` and
    /// `err`. A measured run is Finished and then printed, its `path:` the Finish's; a failed run prints
    /// its line and its error first, and is Finished after. Before a broken run blames the machine,
    /// `stopped` asks whether `serve` itself went: then its line stands alone, with nothing on stdout.
    async fn observed<P: PathSource, S: Session>(
        &self,
        session: &S,
        mut observer: Observer<P>,
        machine: &Machine,
        stopped: impl AsyncFnOnce() -> Option<eyre::Report>,
        out: &mut impl Write,
        err: &mut impl Write,
    ) -> eyre::Result<()> {
        let label = machine.label();
        let report = if self.verbose {
            // Both live callbacks print, one per probe and one per move, so they share the writer.
            let live = RefCell::new(&mut *out);
            let mut shown = observer.latest().path.clone();
            let written = writeln!(live.borrow_mut(), "{}", path_line(&label, &shown));
            if let Err(error) = written {
                return Err(through_serve::failed(error.into(), observer, err).await);
            }
            // A live row that cannot be written is dropped: the block after the run, which carries the
            // result, reports the failed write.
            let probes = self.plan().observing(session, |probe| {
                let _ = writeln!(live.borrow_mut(), "{}", probe_line(&label, probe));
            });
            let moves = observer.watch_with(|info| {
                if info.path != shown {
                    shown = info.path.clone();
                    let _ = writeln!(live.borrow_mut(), "{}", path_line(&label, &shown));
                }
            });
            tokio::select! {
                report = probes => report,
                never = moves => match never {},
            }
        } else {
            tokio::select! {
                report = self.plan().run(session) => report,
                never = observer.watch() => match never {},
            }
        };
        let (line, outcome) = match report {
            Ok(report) => {
                let observed = observer.finish().await;
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
            // No session here to ask one of your devices why, so the refusal names no cause it cannot
            // tell, as an Open refused this way does.
            Err(ProtocolError::Refused(Refusal::Stream(bifrost::Refusal::NotAdmitted))) => {
                let service: Service = reach::PING_SERVICE.parse()?;
                let refused = machine::refused(machine, &service, None);
                return Err(through_serve::failed(refused, observer, err).await);
            }
            Err(ProtocolError::Refused(refusal)) => {
                (refused_line(&label, &refusal), reach::Outcome::Refused)
            }
            // A broken run asks whether `serve` went first: then the machine is not to blame.
            Err(error) => match stopped().await {
                Some(gone) => return Err(through_serve::failed(gone, observer, err).await),
                None => (failed_line(&label, &error), reach::Outcome::Failed),
            },
        };
        // A line that cannot be written ends the run as a failure, Finished all the same.
        if let Err(error) = writeln!(out, "{line}") {
            return Err(through_serve::failed(error.into(), observer, err).await);
        }
        through_serve::ended(outcome.unbound_result(&self.peer), observer, err).await
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

/// Drive `probes` to its end while every path `changes` reports goes to `said`: the path in force first,
/// before the first probe is sent, then each change as the transport selects it. Polled on this task, so a
/// change prints between the probe lines it fell between, and nothing outlives the run: a change after the
/// last probe is not printed, and a stream that ended (a transport whose path never moves) simply stops.
async fn watching<R>(
    changes: PathChanges,
    probes: impl Future<Output = R>,
    mut said: impl FnMut(&Path),
) -> R {
    let mut changes = changes.fuse();
    let mut probes = core::pin::pin!(probes);
    loop {
        tokio::select! {
            // Biased, so the path in force, ready at once, prints before the first probe line.
            biased;
            Some(path) = changes.next() => said(&path),
            report = &mut probes => return report,
        }
    }
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

/// The line `ping` prints, and how far it got, for an Open through `serve` the resident refused, where
/// the own bind prints its own line for the same outcome; the refusal back where the line is the
/// resident's (its cap, an ended standing, this machine, or a peer that did not admit the probe). A
/// timeout reads `unreachable`: the resident cannot say whether the dial or the stream timed out, and
/// `unreachable` never claims a reach that did not happen.
fn own_line(label: &str, refusal: OpenRefusal) -> Result<(String, reach::Outcome), OpenRefusal> {
    match refusal {
        OpenRefusal::Unreachable(detail) => {
            tracing::debug!(%detail, "serve did not reach the machine");
            Ok((format!("{label}: unreachable"), reach::Outcome::Unreachable))
        }
        OpenRefusal::Timeout => {
            tracing::debug!("serve's open to the machine timed out");
            Ok((format!("{label}: unreachable"), reach::Outcome::Unreachable))
        }
        OpenRefusal::Peer(PeerRefusal::NotAdmitted) => Err(refusal),
        OpenRefusal::Peer(peer) => {
            let refusal = Refusal::Stream(bifrost::Refusal::from(peer));
            Ok((refused_line(label, &refusal), reach::Outcome::Refused))
        }
        OpenRefusal::Broken(detail) | OpenRefusal::PeerUnreadable(detail) => Ok((
            failed_cause_line(label, &detail.to_string()),
            reach::Outcome::Failed,
        )),
        OpenRefusal::Busy | OpenRefusal::StandingEnded | OpenRefusal::NotHere => Err(refusal),
    }
}

#[cfg(test)]
mod tests {
    use bifrost::Relay;

    use super::*;

    const RTT: Option<Duration> = Some(Duration::from_millis(24));

    /// `ping` to one of your devices that refuses it prints the dial refusal once, as the error, after
    /// asking the device why over a second connection to it; nothing reaches stdout.
    #[tokio::test]
    async fn a_refused_ping_to_your_device_names_the_cause() {
        use clap::Parser as _;
        use swoosh::testkit::{Script, ScriptedPeer};

        #[derive(clap::Parser)]
        struct Wrap {
            #[command(flatten)]
            ping: PingCmd,
        }

        let key = bifrost::NodeId::from_ed25519_secret(&[0x67; 32]);
        let mut contacts = swoosh::contacts::Contacts::default();
        contacts
            .save(&"me/nas".parse().expect("a device"), key)
            .expect("the name is free");
        let cmd = Wrap::try_parse_from(["x", "me/nas"])
            .expect("ping parses")
            .ping;
        let machine = cmd.peer.machine(&contacts).expect("one machine");
        let peer = ScriptedPeer::new(
            key,
            [
                Script::Refuse(bifrost::Refusal::NotAdmitted),
                Script::Lists(vec!["ping"]),
            ],
        );
        let node = Node::new(peer.clone(), bifrost::NoDiscovery);
        let bound = transport::Bound {
            local: false,
            reach: transport::Reach::default(),
        };
        let error = cmd
            .run_ping(
                &node,
                &machine,
                &bound,
                None,
                None,
                swoosh::learn::Admitted::unheard(),
            )
            .await
            .expect_err("a refused ping exits non-zero");
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
        assert_eq!(asked, ["ping", "control.services"]);
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
        for (refused, line, error) in [
            (
                busy,
                "me/nas: reached, but refused (unavailable: busy)\n",
                "stderr: error: me/nas: reached, but refused",
            ),
            (
                bifrost::Refusal::NotAdmitted,
                "",
                "stderr: error: me/nas refused ping",
            ),
        ] {
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

    /// Through `serve`, an Open the resident refused prints the own bind's line on stdout and its
    /// error, with no reach hint; a timeout reads `unreachable`. The resident's own refusals, and a
    /// peer that did not admit the probe, keep the resident's line.
    #[test]
    fn an_open_refused_through_serve_prints_the_own_binds_line() {
        use swoosh::serve::control_codec::{OpenRefusal, PeerRefusal};

        let detail = || bifrost::RefusalDetail::bounded("busy");
        let peer: Peer = "me/nas".parse().expect("a machine");
        for (refusal, line, error) in [
            (
                OpenRefusal::Unreachable(detail()),
                "me/nas: unreachable",
                "could not reach me/nas",
            ),
            (
                OpenRefusal::Timeout,
                "me/nas: unreachable",
                "could not reach me/nas",
            ),
            (
                OpenRefusal::Peer(PeerRefusal::Unavailable(detail())),
                "me/nas: reached, but refused (unavailable: busy)",
                "me/nas: reached, but refused",
            ),
            (
                OpenRefusal::Peer(PeerRefusal::BadRequest(detail())),
                "me/nas: reached, but refused (bad request: busy)",
                "me/nas: reached, but refused",
            ),
            (
                OpenRefusal::Broken(bifrost::RefusalDetail::bounded("reset\r")),
                r"me/nas: reached, but the probe failed (reset\r)",
                "me/nas: reached, but the probe failed",
            ),
            (
                OpenRefusal::PeerUnreadable(detail()),
                "me/nas: reached, but the probe failed (busy)",
                "me/nas: reached, but the probe failed",
            ),
        ] {
            let (printed, outcome) = own_line("me/nas", refusal).expect("the own bind's line");
            assert_eq!(printed, line);
            let report = outcome.unbound_result(&peer).expect_err("exit 1");
            assert_eq!(format!("{report:#}"), error);
        }
        for resident in [
            OpenRefusal::Peer(PeerRefusal::NotAdmitted),
            OpenRefusal::Busy,
            OpenRefusal::StandingEnded,
            OpenRefusal::NotHere,
        ] {
            assert!(own_line("me/nas", resident).is_err());
        }
    }

    /// How long a test lets `watching` run before calling it hung: a run that waits on a stream that never
    /// ends fails here instead of hanging the suite.
    const HUNG: Duration = Duration::from_secs(5);

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

    /// `-v` prints the path the session reports: the one in force before the first probe, then a line for
    /// each change, between the probe lines it fell between. The stream here is the session's, not a sample
    /// per probe: a relayed session that punches to direct mid-run says so once, at the change.
    #[tokio::test]
    async fn ping_v_prints_a_line_when_the_path_changes() {
        let lines = core::cell::RefCell::new(Vec::new());
        let (changed, change) = futures::channel::mpsc::unbounded();
        changed
            .unbounded_send(relayed("relay.example"))
            .expect("the stream is open");
        let probes = async {
            for seq in 0..3 {
                // The punch lands after the second probe.
                if seq == 2 {
                    changed
                        .unbounded_send(Path::Direct)
                        .expect("the stream is open");
                    tokio::task::yield_now().await;
                }
                let line = probe_line("alice/macbook", Probe { seq, rtt: RTT });
                lines.borrow_mut().push(line);
                tokio::task::yield_now().await;
            }
        };
        let run = watching(PathChanges::new(change), probes, |path| {
            lines.borrow_mut().push(path_line("alice/macbook", path));
        });
        tokio::time::timeout(HUNG, run)
            .await
            .expect("the run ends with its last probe, not with the stream");
        assert_eq!(
            lines.into_inner(),
            [
                "alice/macbook, path: relayed through relay.example",
                "alice/macbook, seq 0 rtt 24.000 ms",
                "alice/macbook, seq 1 rtt 24.000 ms",
                "alice/macbook, path: direct",
                "alice/macbook, seq 2 rtt 24.000 ms",
            ]
        );
    }

    /// A transport whose path never moves (mem) hands `-v` a stream that says its one path
    /// and ends. That prints the one path line, then every probe still prints and the run completes: the
    /// ended stream neither stops the probes nor stalls them.
    #[tokio::test]
    async fn ping_v_runs_every_probe_after_the_path_stream_ends() {
        let lines = core::cell::RefCell::new(Vec::new());
        let probes = async {
            for seq in 0..3 {
                let line = probe_line("alice/macbook", Probe { seq, rtt: RTT });
                lines.borrow_mut().push(line);
                tokio::task::yield_now().await;
            }
        };
        let run = watching(PathChanges::fixed(Path::Direct), probes, |path| {
            lines.borrow_mut().push(path_line("alice/macbook", path));
        });
        tokio::time::timeout(HUNG, run)
            .await
            .expect("the run ends with its last probe after the stream ended");
        assert_eq!(
            lines.into_inner(),
            [
                "alice/macbook, path: direct",
                "alice/macbook, seq 0 rtt 24.000 ms",
                "alice/macbook, seq 1 rtt 24.000 ms",
                "alice/macbook, seq 2 rtt 24.000 ms",
            ]
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
