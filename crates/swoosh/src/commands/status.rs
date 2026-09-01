//! `swoosh status <peer>`: dial a peer and report the connection path, Tailscale `status` shaped.
//!
//! The single most reassuring thing a p2p tool tells you: am I actually peer to peer, or bouncing off a
//! relay? For each device the peer resolves to, this dials it, runs a single measure ping for a live RTT,
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
use measure::{Ping, ProtocolError};

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

        // Report each device; track whether any device was HEALTHY (reached and served the probe), so a
        // fan-out where every device was unreachable OR refused ends non-zero rather than exiting clean
        // on a screen full of failures. A refused device answered the dial but does not serve ping, so it
        // is not healthy: it must not hold the exit code green the way a real status line does.
        let mut any_healthy = false;
        for candidate in &candidates {
            let line =
                match reach::connect_service(node, candidate, reach::PING_SERVICE, present.clone())
                    .await
                {
                    Ok(session) => probe(&session, &candidate.label, transport).await,
                    Err(_error) => Line::unreachable(&candidate.label, transport.name()),
                };
            any_healthy |= line.is_healthy();
            println!("{line}");
        }

        node.close().await;
        if any_healthy {
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

    // A single measure ping for a fresh, honest RTT. Some transports (quirk) carry no rtt estimator, so
    // conn_info().rtt is None there; one probe measures the round trip the same way over any of them.
    let probed = Ping {
        count: 1,
        interval: Duration::ZERO,
    }
    .run(session)
    .await;

    // A refusal is NOT a healthy line with a borrowed transport RTT. The node reached us but does not
    // serve ping, so render a distinct `refused` line rather than `.ok()`-swallowing the error and
    // reporting the transport's own path RTT as if the probe had succeeded. That swallow is exactly what
    // made a refusing node look fully healthy; a typed `Refused` is a first-class outcome here.
    if let Err(ProtocolError::Refused(reason)) = &probed {
        return Line::refused(label.to_owned(), transport.name(), reason.clone());
    }

    // Read the path AFTER the probe, not before: the round trip gives iroh's hole-punch a moment to
    // land, so a session that starts relayed and upgrades reports "direct" here instead of always
    // showing the pre-upgrade "relayed" it had the instant it connected.
    let info = session.conn_info();
    let rtt = probed.ok().and_then(|report| report.avg()).or(info.rtt);
    Line::reached(label.to_owned(), transport.name(), initial, info, rtt)
}

/// A rendered status line for one device: reachable (path + RTT), unreachable, or reached-but-refused.
struct Line {
    /// The device as the user named it, or the reached key's short form.
    label: String,
    transport: &'static str,
    state: State,
}

/// The outcome for one device. A refusal is a first-class state, distinct from both reachable and
/// unreachable: the node answered the dial but does not serve ping, so it is neither a healthy path line
/// nor an "unreachable". Making it its own variant is what stops a refusal from rendering as a healthy
/// line with a borrowed transport RTT.
enum State {
    /// The device answered the probe: the path at connect, the path after the probe, and the RTT.
    /// `initial` lets the phrase report a relayed-to-direct upgrade that landed during probing.
    Reached {
        initial: Path,
        info: ConnInfo,
        rtt: Option<Duration>,
    },
    /// The device did not answer the dial at all.
    Unreachable,
    /// The device answered but refused the ping probe (it does not serve ping), carrying the host's reason.
    Refused { reason: String },
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
            state: State::Reached { initial, info, rtt },
        }
    }

    fn unreachable(label: &str, transport: &'static str) -> Self {
        Self {
            label: label.to_owned(),
            transport,
            state: State::Unreachable,
        }
    }

    fn refused(label: String, transport: &'static str, reason: String) -> Self {
        Self {
            label,
            transport,
            state: State::Refused { reason },
        }
    }

    /// Whether this device answered the probe (a real status line), as opposed to being unreachable or
    /// having refused. Only a healthy device keeps the fan-out's exit code green.
    fn is_healthy(&self) -> bool {
        matches!(self.state, State::Reached { .. })
    }
}

impl core::fmt::Display for Line {
    /// `<peer> via <transport>: <path>[, rtt <n>]`, Tailscale-status shaped, or `<peer> via <transport>:
    /// unreachable` for a device that did not answer, or `<peer> via <transport>: refused (<reason>)` for
    /// a node that answered but does not serve ping. The path phrase (shared with `ping`/`speed`) names
    /// the remote when a direct address is known, and reports a relayed-to-direct upgrade when one landed.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} via {}: ", self.label, self.transport)?;
        match &self.state {
            State::Unreachable => f.write_str("unreachable"),
            State::Refused { reason } => write!(f, "refused ({reason})"),
            State::Reached { initial, info, rtt } => {
                write!(f, "{}", reach::conn_path(*initial, info))?;
                if let Some(rtt) = rtt {
                    write!(f, ", rtt {:.3} ms", rtt.as_secs_f64() * 1000.0)?;
                }
                Ok(())
            }
        }
    }
}
