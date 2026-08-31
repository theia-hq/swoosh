//! `swoosh status <peer>`: dial a peer and report the connection path, Tailscale `status` shaped.
//!
//! The single most reassuring thing a p2p tool tells you: am I actually peer to peer, or bouncing off a
//! relay? For each device the peer resolves to, this dials it, runs a single diag ping for a live RTT,
//! then reads the session's best-effort [`conn_info`](bifrost::Session::conn_info) for the path (direct
//! vs relayed) and remote address, and prints one line. The path is read AFTER the probe so iroh's
//! hole-punch has the round trip to land: a session that connects relayed and upgrades reports the
//! upgraded path, not the instant-of-connect one. Over quirk it says direct; over iroh it reports the
//! current path, which can still be relayed if the upgrade has not completed by then.
//!
//! A person (`alice`) fans out to ALL her devices, one status line each, since "how do I reach alice,
//! across her devices" is exactly the diagnostic; `alice/macbook` reports the one. One-shot: swoosh has
//! no daemon, so this reports the devices you name. Listing the whole tailnet of active sessions
//! (Tailscale's full `status`) needs a long-lived node holding those sessions; that is future work.

use core::time::Duration;

use bifrost::{ConnInfo, Discovery, Node, Path, Session, Transport};
use clap::Args;
use diag::Ping;

use crate::contacts::{Contacts, Target};
use crate::reach;
use crate::transport::{self, ReachArgs};

/// Report the connection path to a peer: transport, direct vs relayed, remote address, and live RTT.
#[derive(Debug, Args)]
pub struct StatusCmd {
    /// The peer to reach: a saved petname (`alice`, `alice/macbook`) or a raw bifrost node id.
    #[arg(value_name = "peer")]
    pub target: Target,
    /// Present a membership badge or capability link to a family/cap-gated peer. Defaults to the
    /// self-signed badge minted from this identity when it dials under a persisted key.
    #[arg(long, value_name = "link")]
    pub present: Option<String>,
    #[command(flatten)]
    pub reach: ReachArgs,
}

impl StatusCmd {
    /// Resolve the target to its devices, and for each dial, probe the path and a single RTT, and print a
    /// status line. Reports every device (a person fans out); an unreachable one prints an honest line
    /// rather than aborting the rest.
    pub async fn run<T: Transport, D: Discovery>(
        self,
        node: &Node<T, D>,
        contacts: &Contacts,
        transport: transport::Transport,
        self_badge: Option<String>,
    ) -> eyre::Result<()> {
        let candidates = reach::candidates(&self.target, contacts)?;
        // Present an explicit `--present` link if given, else the self-signed badge minted from this
        // identity: the peer's `ping` service is gated, so the RTT probe must prove membership to run.
        let present = self.present.or(self_badge);

        // Report each device; track whether any was reachable, so an all-unreachable fan-out ends non-
        // zero with the transport's fix hint, not a bare list of failures.
        let mut any_reached = false;
        for candidate in &candidates {
            let line =
                match reach::connect_service(node, candidate, reach::PING_SERVICE, present.clone())
                    .await
                {
                    Ok(session) => {
                        any_reached = true;
                        probe(&session, &candidate.label, transport).await
                    }
                    Err(_error) => Line::unreachable(&candidate.label, transport.name()),
                };
            println!("{line}");
        }

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

/// Probe one reached session for a live RTT and its path, and render its status line under `label` (the
/// device as the user named it, so a fan-out reads by device, matching `ping`).
async fn probe<S: Session>(session: &S, label: &str, transport: transport::Transport) -> Line {
    // Sample the path at connect, before the probe, so we can tell whether iroh's hole-punch upgraded a
    // relayed path to direct during the round trip below.
    let initial = session.conn_info().path;

    // A single diag ping for a fresh, honest RTT. Some transports (quirk) carry no rtt estimator, so
    // conn_info().rtt is None there; one probe measures the round trip the same way over any of them.
    let probed = Ping {
        count: 1,
        interval: Duration::ZERO,
    }
    .run(session)
    .await;

    // Read the path AFTER the probe, not before: the round trip gives iroh's hole-punch a moment to
    // land, so a session that starts relayed and upgrades reports "direct" here instead of always
    // showing the pre-upgrade "relayed" it had the instant it connected.
    let info = session.conn_info();
    let rtt = probed.ok().and_then(|report| report.avg()).or(info.rtt);
    Line::reached(label.to_owned(), transport.name(), initial, info, rtt)
}

/// A rendered status line for one device: reachable (path + RTT) or not.
struct Line {
    /// The device as the user named it, or the reached key's short form.
    label: String,
    transport: &'static str,
    /// The path and RTT, or `None` when the device was unreachable.
    reached: Option<Reached>,
}

/// The reachable half of a [`Line`]: the path at connect, the path after the probe, and the round-trip
/// time. `initial` lets the rendered phrase report a relayed-to-direct upgrade that landed during probing.
struct Reached {
    initial: Path,
    info: ConnInfo,
    rtt: Option<Duration>,
}

impl Line {
    fn reached(
        label: String,
        transport: &'static str,
        initial: Path,
        info: ConnInfo,
        rtt: Option<Duration>,
    ) -> Self {
        Self {
            label,
            transport,
            reached: Some(Reached { initial, info, rtt }),
        }
    }

    fn unreachable(label: &str, transport: &'static str) -> Self {
        Self {
            label: label.to_owned(),
            transport,
            reached: None,
        }
    }
}

impl core::fmt::Display for Line {
    /// `<peer> via <transport>: <path>[, rtt <n>]`, Tailscale-status shaped, or `<peer> via <transport>:
    /// unreachable` for a device that did not answer. The path phrase (shared with `ping`/`speed`) names
    /// the remote when a direct address is known, and reports a relayed-to-direct upgrade when one landed.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} via {}: ", self.label, self.transport)?;
        match &self.reached {
            None => f.write_str("unreachable"),
            Some(Reached { initial, info, rtt }) => {
                write!(f, "{}", reach::conn_path(*initial, info))?;
                if let Some(rtt) = rtt {
                    write!(f, ", rtt {:.3} ms", rtt.as_secs_f64() * 1000.0)?;
                }
                Ok(())
            }
        }
    }
}
