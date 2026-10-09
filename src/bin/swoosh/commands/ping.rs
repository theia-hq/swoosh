//! `swoosh ping <machine>`: reach one machine by name or key and report round-trip time, `ping(8)` shaped.
//!
//! One machine, always: `alice/macbook` pings that one, and a bare person pings their one saved machine
//! (several refuse before anything binds). The block names the machine, then its `path:` (`direct` or
//! `relayed through <relay>`, the same words `status` prints) so a slow RTT reads as "it relayed", not a
//! mystery, then the `ping(8)` counts/loss and RTT distribution.
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
use swoosh::escape::{Escaped, causes};
use swoosh::learn::Admitted;
use swoosh::peer::{Machine, Peer};
use swoosh::reach;
use swoosh::transport::{self, ReachArgs};

use crate::commands::machine;

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
    ) -> eyre::Result<()> {
        // Slots 1 and 2 are ALREADY resolved by the composition root's ONE resolver: slot 1 (`present`) is
        // the link typed as the peer or the member badge, slot 2 (`membership`) is a fleet badge only for a
        // signet-bound slip. The verb never threads a slip itself, so it cannot desync the two.
        let plan = Ping {
            count: self.count,
            interval: Duration::from_secs_f64(self.interval),
        };
        let label = machine.label();
        let name = bound.transport.name();
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
            Ok(session) => admitted.watch(session),
            Err(_error) => {
                println!("{label} via {name}: unreachable");
                return reach::Outcome::Unreachable.into_result(&self.peer, bound);
            }
        };
        // With `-v`, print a line per probe as it lands, and a path line for the path in force and each
        // change the session reports, so the moment a relayed link flips to direct is visible live. The
        // observer borrows the session read-only, alongside the run's own read-only borrow.
        let report = if self.verbose {
            let probes = plan.observing(&session, |probe| {
                println!("{}", probe_line(&label, name, probe));
            });
            watching(session.path_changes(), probes, |path| {
                println!("{}", path_line(&label, name, path));
            })
            .await
        } else {
            plan.run(&session).await
        };
        let outcome = match report {
            Ok(report) => {
                let path = reach::conn_path(&session.conn_info()).to_string();
                print_device(&label, name, &path, &report);
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
                println!("{}", refused_line(&label, name, &refusal));
                reach::Outcome::Refused
            }
            // The node was REACHED and the exchange then broke. The full cause chain is rendered because
            // the outer half of a stream failure is routinely the useless half.
            Err(error) => {
                println!("{}", failed_line(&label, name, &error));
                reach::Outcome::Failed
            }
        };

        // The composition root closes the node once anything still running beside the verb has ended, so
        // the last frames land and iroh shuts down cleanly.
        outcome.into_result(&self.peer, bound)
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
            transport: transport::Transport::Iroh,
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
