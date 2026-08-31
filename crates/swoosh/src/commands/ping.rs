//! `swoosh ping <peer>`: reach a peer by petname or public key and report round-trip time, `ping(8)`
//! shaped.
//!
//! ping is a diagnostic, so a person (`alice`) fans out to ALL her devices and reports each: how do I
//! reach alice, across every device she has? `alice/macbook` pings the one. Each device's block leads
//! with the connection path (direct vs relayed, the same source `status` reads) so a slow RTT reads as
//! "it relayed", not a mystery, then the `ping(8)` counts/loss and RTT distribution.
//!
//! With `-v`, it prints a line per probe as each one lands (like `tailscale ping`), sampling the path
//! beside every pong so you WATCH a relayed iroh link hole-punch to direct: the exact probe where it
//! flips prints `(upgraded from relayed)`. The `ping(8)` summary still follows the live lines.

use core::time::Duration;

use bifrost::{ConnInfo, Discovery, Node, Path, Session, Transport};
use clap::Args;
use diag::{Ping, PingReport, Probe};

use crate::contacts::{Contacts, Target};
use crate::reach;
use crate::transport::{self, ReachArgs};

/// Measure the round-trip time to a peer, addressed by a petname or their public key.
#[derive(Debug, Args)]
pub struct PingCmd {
    /// The peer to reach: a saved petname (`alice`, `alice/macbook`) or a raw bifrost node id.
    #[arg(value_name = "peer")]
    pub target: Target,
    /// How many probes to send.
    #[arg(short = 'c', long, value_name = "count", default_value_t = 4)]
    pub count: u32,
    /// Seconds between probes.
    #[arg(short = 'i', long, value_name = "seconds", default_value_t = 1.0)]
    pub interval: f64,
    /// Present a membership badge or capability link to a family/cap-gated peer. Defaults to the
    /// self-signed badge minted from this identity when it dials under a persisted key.
    #[arg(long, value_name = "link")]
    pub present: Option<String>,
    /// Print a line per probe as it lands, showing the path at that moment (watch iroh punch to direct).
    #[arg(short = 'v', long)]
    pub verbose: bool,
    #[command(flatten)]
    pub reach: ReachArgs,
}

impl PingCmd {
    /// Resolve the target to its devices, and for each dial, probe, and print its path and RTT summary.
    /// Reports every device (a person fans out); an unreachable one prints an honest line and the run
    /// continues, ending non-zero only if no device answered at all.
    pub async fn run<T: Transport, D: Discovery>(
        self,
        node: &Node<T, D>,
        contacts: &Contacts,
        transport: transport::Transport,
        self_badge: Option<String>,
    ) -> eyre::Result<()> {
        let candidates = reach::candidates(&self.target, contacts)?;
        // Present an explicit `--present` link if given, else the self-signed badge minted from this
        // identity: the peer's `diag.ping` service is gated, so each probe must prove membership to run.
        let present = self.present.or(self_badge);
        let plan = Ping {
            count: self.count,
            interval: Duration::from_secs_f64(self.interval),
        };

        let mut any_reached = false;
        for candidate in &candidates {
            match reach::connect_service(node, candidate, reach::PING_SERVICE, present.clone())
                .await
            {
                Ok(session) => {
                    any_reached = true;
                    // Path at connect, so the phrases below can report a relayed-to-direct upgrade that
                    // the probe's round trips gave iroh's hole-punch time to land.
                    let initial = session.conn_info().path;
                    // With `-v`, print a line per probe as it lands, sampling the path beside each pong so
                    // the exact probe where a relayed link flips to direct is visible live. The observer
                    // borrows the session read-only, alongside the run's own read-only borrow.
                    let report = if self.verbose {
                        let label = &candidate.label;
                        let name = transport.name();
                        plan.observing(&session, |probe| {
                            println!(
                                "{}",
                                probe_line(label, name, initial, &session.conn_info(), probe)
                            );
                        })
                        .await?
                    } else {
                        plan.run(&session).await?
                    };
                    let path = reach::conn_path(initial, &session.conn_info());
                    print_device(&candidate.label, transport.name(), &path, &report);
                }
                Err(_error) => {
                    println!("{} via {}: unreachable", candidate.label, transport.name());
                }
            }
        }

        // Drain and close the transport so the last frames land and iroh shuts down cleanly.
        node.close().await;
        if any_reached {
            Ok(())
        } else {
            Err(reach::hint(
                eyre::eyre!("could not reach {}", self.target),
                transport,
            ))
        }
    }
}

/// Print one device's block: the path line (status-shaped), then the `ping(8)` counts and RTT
/// distribution indented beneath it.
fn print_device(label: &str, transport: &str, path: &str, report: &PingReport) {
    println!("{label} via {transport}: {path}");
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

/// One live probe line: `<label> via <transport>: <path>, seq <n> rtt <x> ms` (or `... lost` for a
/// dropped reply), `tailscale ping` shaped. `initial` is the path at connect and `info` the path at this
/// probe, so the path phrase (shared with `status`/`speed` via [`conn_path`](reach::conn_path)) reports
/// `(upgraded from relayed)` on the exact probe a relayed link first flips to direct, and plain `direct`
/// or `relayed` otherwise. A direct-from-connect run never claims an upgrade; a stays-relayed run never
/// does either.
fn probe_line(
    label: &str,
    transport: &str,
    initial: Path,
    info: &ConnInfo,
    probe: Probe,
) -> String {
    let path = reach::conn_path(initial, info);
    match probe.rtt {
        Some(rtt) => format!(
            "{label} via {transport}: {path}, seq {} rtt {:.3} ms",
            probe.seq,
            millis(rtt)
        ),
        None => format!("{label} via {transport}: {path}, seq {} lost", probe.seq),
    }
}

/// A duration as fractional milliseconds, the unit ping reports.
fn millis(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

#[cfg(test)]
mod tests {
    use core::net::SocketAddr;

    use super::*;

    /// A `ConnInfo` with a given path, and a remote address for the direct cases (so the phrase can name
    /// it, matching a real iroh session). Relayed/unknown carry no remote, as the transport reports.
    fn info(path: Path) -> ConnInfo {
        let remote = matches!(path, Path::Direct | Path::Mixed).then(|| {
            "203.0.113.7:41641"
                .parse::<SocketAddr>()
                .expect("valid addr")
        });
        ConnInfo {
            path,
            rtt: None,
            remote,
        }
    }

    /// Render the live lines for a synthetic per-probe path sequence, exactly as the `-v` observer does:
    /// `initial` is the path at connect, then one `(path, rtt)` per probe. Lets a test drive a
    /// relayed-then-direct flip without a network and assert on the phrasing.
    fn lines(initial: Path, probes: &[(Path, Option<Duration>)]) -> Vec<String> {
        probes
            .iter()
            .enumerate()
            .map(|(seq, &(path, rtt))| {
                let probe = Probe {
                    seq: seq as u32,
                    rtt,
                };
                probe_line("alice/macbook", "iroh", initial, &info(path), probe)
            })
            .collect()
    }

    const RTT: Option<Duration> = Some(Duration::from_millis(24));

    #[test]
    fn a_relayed_to_direct_sequence_shows_the_upgrade_on_the_flip_probe() {
        // Connected relayed, then hole-punched to direct on the third probe: the first two lines read
        // relayed, and every direct line from the flip on names the upgrade, so the moment is visible.
        let lines = lines(
            Path::Relayed,
            &[
                (Path::Relayed, RTT),
                (Path::Relayed, RTT),
                (Path::Direct, RTT),
                (Path::Direct, RTT),
            ],
        );
        assert_eq!(
            lines[0],
            "alice/macbook via iroh: relayed, seq 0 rtt 24.000 ms"
        );
        assert_eq!(
            lines[1],
            "alice/macbook via iroh: relayed, seq 1 rtt 24.000 ms"
        );
        assert_eq!(
            lines[2],
            "alice/macbook via iroh: direct to 203.0.113.7:41641 (upgraded from relayed), seq 2 rtt 24.000 ms"
        );
        assert!(
            lines[2].contains("upgraded from relayed"),
            "the flip probe must announce the upgrade: {}",
            lines[2]
        );
        assert!(
            lines[3].contains("upgraded from relayed"),
            "later direct lines still credit the upgrade: {}",
            lines[3]
        );
    }

    #[test]
    fn a_stays_relayed_sequence_never_claims_an_upgrade() {
        let lines = lines(Path::Relayed, &[(Path::Relayed, RTT); 3]);
        for line in &lines {
            assert!(line.contains("relayed"), "each line stays relayed: {line}");
            assert!(
                !line.contains("upgraded"),
                "a run that never punches through must not claim an upgrade: {line}"
            );
            assert!(
                !line.contains("direct"),
                "a stays-relayed run never reports direct: {line}"
            );
        }
    }

    #[test]
    fn a_direct_throughout_sequence_stays_direct_and_never_claims_an_upgrade() {
        // Quirk (and an iroh session already direct at connect): direct from the first probe, and since
        // it never started relayed, no line claims an upgrade it did not make.
        let lines = lines(Path::Direct, &[(Path::Direct, RTT); 3]);
        for line in &lines {
            assert!(
                line.contains("direct to 203.0.113.7:41641"),
                "each line is direct: {line}"
            );
            assert!(
                !line.contains("upgraded"),
                "direct-from-connect must never claim an upgrade: {line}"
            );
        }
    }

    #[test]
    fn a_lost_probe_reports_lost_not_a_zero_rtt() {
        let lines = lines(Path::Direct, &[(Path::Direct, None)]);
        assert_eq!(
            lines[0],
            "alice/macbook via iroh: direct to 203.0.113.7:41641, seq 0 lost"
        );
    }
}
