//! `swoosh ping <peer>`: reach a peer by petname or public key and report round-trip time, `ping(8)`
//! shaped.
//!
//! ping is a diagnostic, so a person (`alice`) fans out to ALL her devices and reports each: how do I
//! reach alice, across every device she has? `alice/macbook` pings the one. Each device's block names
//! the device, then its `path:` (`direct` or `relayed through <relay>`, the same words `status` prints) so
//! a slow RTT reads as "it relayed", not a mystery, then the `ping(8)` counts/loss and RTT distribution.
//!
//! With `-v`, it prints a line per probe as each one lands (like `tailscale ping`), and a `path:` line for
//! the path in force when the probes start and again each time the transport selects another, from the
//! session's own stream of path changes rather than a sample beside each pong, so you WATCH a relayed iroh
//! link hole-punch to direct at the moment it does. The `ping(8)` summary still follows the live lines.

use core::future::Future;
use core::time::Duration;

use bifrost::{Discovery, Node, Path, PathChanges, Session, Transport};
use clap::Args;
use futures::StreamExt as _;
use measure::{Ping, PingReport, Probe, ProtocolError, Refusal};
use nauthy::{Link, Service};
use swoosh::contacts::Contacts;
use swoosh::escape::{Escaped, causes};
use swoosh::peer::Peer;
use swoosh::reach;
use swoosh::transport::{self, ReachArgs};

/// Measure the round-trip time to a peer, addressed by a petname or their public key.
#[derive(Debug, Args)]
pub struct PingCmd {
    /// the peer to reach: a petname (`alice`, `alice/desk`), a raw node id, or a `swoosh:` link
    #[arg(value_name = "peer")]
    pub peer: Peer,
    /// how many probes to send
    #[arg(short = 'c', long, value_name = "count", default_value_t = 4)]
    pub count: u32,
    /// seconds between probes
    #[arg(short = 'i', long, value_name = "seconds", default_value_t = 1.0)]
    pub interval: f64,
    /// present a `swoosh:` capability link to reach a gated peer
    #[arg(
        long,
        value_name = "link",
        value_parser = swoosh::link::parse,
        long_help = "Optional: your own devices need no link, the dial presents this \
                     device's membership badge. Pass a `swoosh:` link only to reach as a delegate."
    )]
    pub present: Option<Link>,
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

    fn reject_redundant_present(&self) -> eyre::Result<()> {
        self.peer.reject_redundant_present(self.present.as_ref())
    }

    fn identity(&self) -> swoosh::identity::Identity {
        self.bind_role().identity()
    }

    /// Dialing, and what it dials as. It reaches a peer and never accepts connections under the
    /// home key, so its bind must not write the key's address record (0.9.0 F1).
    ///
    /// `ping` reaches the peer's family-gated `ping` service, so it presents the member badge rooted at
    /// the dialing key. Stating `Family` FUSES the identity to `PersistedIfPresent`, so the self-badge
    /// roots correctly. A `--present` slip is threaded INTO the credential so the ONE resolver
    /// ([`resolve`](swoosh::reaching::resolve)) owns both slots: slot 1 (present-or-badge) and the
    /// privacy-aware slot 2 (a fleet badge, only for a signet-bound slip). The effective slip is the FOLD of
    /// a self-addressing `swoosh:` link-as-peer with an explicit `--present`, so a link-as-peer resolves
    /// through the same slot path as a `--present` link.
    ///
    /// An `anyone` link typed as the peer presents alone, under a throwaway key (`Credential::dialing`).
    fn bind_role(&self) -> swoosh::reaching::BindRole {
        swoosh::reaching::BindRole::Dialing(swoosh::credential::Credential::dialing(
            &self.peer,
            self.present.clone(),
            reach::PING_SERVICE,
        ))
    }

    /// Uniform dispatch: unpack the reach context and run. `ping` reads `contacts` (fan-out), the
    /// `transport` label, and the resolved `present` badge; it ignores `key`.
    async fn run<T: Transport, D: Discovery>(
        self,
        node: &Node<T, D>,
        ctx: swoosh::reaching::ReachCtx<'_>,
    ) -> eyre::Result<()>
    where
        <T::Session as Session>::Write: Send + 'static,
        <T::Session as Session>::Read: Send + 'static,
    {
        self.run_ping(node, ctx.contacts, ctx.bound, ctx.present, ctx.membership)
            .await
    }
}

impl PingCmd {
    /// Resolve the target to its devices, and for each dial, probe, and print its path and RTT summary.
    /// Reports every device (a person fans out); an unreachable one prints an honest line and the run
    /// continues, ending non-zero only if no device answered at all.
    async fn run_ping<T: Transport, D: Discovery>(
        self,
        node: &Node<T, D>,
        contacts: &Contacts,
        bound: &transport::Bound,
        present: Option<Link>,
        membership: Option<Link>,
    ) -> eyre::Result<()> {
        // The redundant-present conflict (a `swoosh:` link peer plus an explicit `--present`) is rejected
        // ONCE in the composition root via `Reaching::reject_redundant_present`, before this runs.
        let candidates = reach::candidates(&self.peer, contacts)?;
        // Slots 1 and 2 are ALREADY resolved by the composition root's ONE resolver: slot 1 (`present`) is
        // the `--present` slip or the member badge, slot 2 (`membership`) is a fleet badge only for a
        // signet-bound slip. The verb no longer threads `--present` itself, so it cannot desync the two.
        let plan = Ping {
            count: self.count,
            interval: Duration::from_secs_f64(self.interval),
        };

        // Fold how far each device got, so a fan-out where every device was unreachable OR refused ends
        // non-zero. A refused device answered the dial but does not serve ping, so it prints a distinct
        // line and does not hold the exit code green: a refusal is never rendered as `100% loss`.
        let mut outcome = reach::Outcome::default();
        let service: Service = reach::PING_SERVICE.parse()?;
        for candidate in &candidates {
            match reach::connect_service(
                node,
                candidate,
                &service,
                Option::clone(&present),
                Option::clone(&membership),
            )
            .await
            {
                Ok(session) => {
                    // With `-v`, print a line per probe as it lands, and a path line for the path in force
                    // and each change the session reports, so the moment a relayed link flips to direct
                    // is visible live. The observer borrows the session read-only, alongside the run's own
                    // read-only borrow.
                    let report = if self.verbose {
                        let label = &candidate.label;
                        let name = bound.transport.name();
                        let probes = plan.observing(&session, |probe| {
                            println!("{}", probe_line(label, name, probe));
                        });
                        watching(session.path_changes(), probes, |path| {
                            println!("{}", path_line(label, name, path));
                        })
                        .await
                    } else {
                        plan.run(&session).await
                    };
                    match report {
                        Ok(report) => {
                            outcome = outcome.max(reach::Outcome::Healthy);
                            let path = reach::conn_path(&session.conn_info()).to_string();
                            print_device(&candidate.label, bound.transport.name(), &path, &report);
                        }
                        // The node was REACHED but refused this probe: a distinct line that says so (not a
                        // healthy device with 100% loss, and NOT "unreachable"), rendering the typed refusal
                        // so a gate refusal reads descriptively and is never doubled (`refused (refused)`).
                        // The run continues to the next device.
                        Err(ProtocolError::Refused(refusal)) => {
                            outcome = outcome.max(reach::Outcome::Refused);
                            println!(
                                "{}",
                                refused_line(&candidate.label, bound.transport.name(), &refusal)
                            );
                        }
                        // The node was REACHED and the exchange then broke. One broken device used to
                        // abort the whole run with its error, so the devices after it were never tried and
                        // the operator learned nothing about them: a fan-out that gives up on the first
                        // bad peer answers a narrower question than the one asked. It is a line now, like
                        // a refusal and like an unreachable, and the run continues. The full cause chain
                        // is rendered because the outer half of a stream failure is routinely the useless
                        // half.
                        Err(error) => {
                            outcome = outcome.max(reach::Outcome::Failed);
                            println!(
                                "{}",
                                failed_line(&candidate.label, bound.transport.name(), &error)
                            );
                        }
                    }
                }
                Err(_error) => {
                    println!(
                        "{} via {}: unreachable",
                        candidate.label,
                        bound.transport.name()
                    );
                }
            }
        }

        // Drain and close the transport so the last frames land and iroh shuts down cleanly.
        node.close().await;
        reach::fanout_outcome(outcome, &self.peer, bound)
    }
}

/// Print one device's block: the device, its `path:` line, then the `ping(8)` counts and RTT
/// distribution indented beneath it.
fn print_device(label: &str, transport: &str, path: &str, report: &PingReport) {
    println!("{label} via {transport}");
    println!("  path: {path}");
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

/// One path line: `<label> via <transport>, path: <path>`, printed under `-v` for the path in force and
/// for each change.
fn path_line(label: &str, transport: &str, path: &Path) -> String {
    format!("{label} via {transport}, path: {}", reach::PathLine(path))
}

/// One live probe line: `<label> via <transport>, seq <n> rtt <x> ms` (or `... lost` for a dropped reply),
/// `tailscale ping` shaped. The path is not sampled here: it has its own line when it changes.
fn probe_line(label: &str, transport: &str, probe: Probe) -> String {
    match probe.rtt {
        Some(rtt) => format!(
            "{label} via {transport}, seq {} rtt {:.3} ms",
            probe.seq,
            millis(rtt)
        ),
        None => format!("{label} via {transport}, seq {} lost", probe.seq),
    }
}

/// A duration as fractional milliseconds, the unit ping reports.
fn millis(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

/// The line for a device that was reached and refused the probe. The refusal's detail is the peer's
/// text, so it prints through the escaper.
fn refused_line(label: &str, transport: &str, refusal: &Refusal) -> String {
    format!(
        "{label} via {transport}: reached, but refused ({})",
        Escaped(&refusal.to_string())
    )
}

/// The line for a device that was reached and whose exchange then broke.
///
/// Says it was REACHED, so it is never confused with `unreachable`, and names the cause rather than a
/// round-trip time, because a broken exchange measured nothing.
fn failed_line(label: &str, transport: &str, error: &ProtocolError) -> String {
    format!(
        "{label} via {transport}: reached, but the probe failed ({})",
        Escaped(&causes(error))
    )
}

#[cfg(test)]
mod tests {
    use bifrost::Relay;

    use super::*;

    const RTT: Option<Duration> = Some(Duration::from_millis(24));

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
        let line = failed_line("alice/nas", "iroh", &error);

        assert!(
            line.starts_with("alice/nas via iroh: reached, but the probe failed ("),
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
                let line = probe_line("alice/macbook", "iroh", Probe { seq, rtt: RTT });
                lines.borrow_mut().push(line);
                tokio::task::yield_now().await;
            }
        };
        let run = watching(PathChanges::new(change), probes, |path| {
            lines
                .borrow_mut()
                .push(path_line("alice/macbook", "iroh", path));
        });
        tokio::time::timeout(HUNG, run)
            .await
            .expect("the run ends with its last probe, not with the stream");
        assert_eq!(
            lines.into_inner(),
            [
                "alice/macbook via iroh, path: relayed through relay.example",
                "alice/macbook via iroh, seq 0 rtt 24.000 ms",
                "alice/macbook via iroh, seq 1 rtt 24.000 ms",
                "alice/macbook via iroh, path: direct",
                "alice/macbook via iroh, seq 2 rtt 24.000 ms",
            ]
        );
    }

    /// A transport whose path never moves (quirk, mem, noise) hands `-v` a stream that says its one path
    /// and ends. That prints the one path line, then every probe still prints and the run completes: the
    /// ended stream neither stops the probes nor stalls them.
    #[tokio::test]
    async fn ping_v_runs_every_probe_after_the_path_stream_ends() {
        let lines = core::cell::RefCell::new(Vec::new());
        let probes = async {
            for seq in 0..3 {
                let line = probe_line("alice/macbook", "quirk", Probe { seq, rtt: RTT });
                lines.borrow_mut().push(line);
                tokio::task::yield_now().await;
            }
        };
        let run = watching(PathChanges::fixed(Path::Direct), probes, |path| {
            lines
                .borrow_mut()
                .push(path_line("alice/macbook", "quirk", path));
        });
        tokio::time::timeout(HUNG, run)
            .await
            .expect("the run ends with its last probe after the stream ended");
        assert_eq!(
            lines.into_inner(),
            [
                "alice/macbook via quirk, path: direct",
                "alice/macbook via quirk, seq 0 rtt 24.000 ms",
                "alice/macbook via quirk, seq 1 rtt 24.000 ms",
                "alice/macbook via quirk, seq 2 rtt 24.000 ms",
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
            let line = path_line("alice/macbook", "iroh", &path);
            assert!(line.ends_with(said), "{path:?} reads {said}: {line}");
        }
    }

    #[test]
    fn a_lost_probe_reports_lost_not_a_zero_rtt() {
        let line = probe_line("alice/macbook", "iroh", Probe { seq: 0, rtt: None });
        assert_eq!(line, "alice/macbook via iroh, seq 0 lost");
    }

    /// A peer's refusal detail holding a carriage return, an ESC CSI sequence and a bidi override prints
    /// as escapes on one line, so a node that refused cannot redraw its line as a healthy probe.
    #[test]
    fn a_hostile_refusal_prints_escaped() {
        let refusal = Refusal::Stream(bifrost::Refusal::Unavailable {
            detail: bifrost::RefusalDetail::bounded(
                "no\r\u{1b}[2Kalice/macbook via iroh, path: direct, seq 0 rtt 0.4 ms\u{202e}",
            ),
        });
        let line = refused_line("alice/macbook", "iroh", &refusal);
        assert_eq!(
            line,
            r"alice/macbook via iroh: reached, but refused (unavailable: no\r\u{1b}[2Kalice/macbook via iroh, path: direct, seq 0 rtt 0.4 ms\u{202e})"
        );
        assert!(
            !line.contains(['\r', '\n', '\u{1b}', '\u{202e}']),
            "no raw byte of the peer's reaches the line: {line:?}"
        );
    }
}
