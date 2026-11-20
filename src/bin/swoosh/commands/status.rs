//! `swoosh status [<machine>]`: what this machine is, or dial a machine and report the connection path,
//! Tailscale `status` shaped.
//!
//! BARE (`status`, no peer) reads this machine's own files and never dials: its key, its lock, its
//! root, its devices, its contacts, the links it shared, and what a running `serve` serves ([`report`]).
//! `--key` prints the key alone.
//!
//! With a machine: the single most reassuring thing a p2p tool tells you: am I actually peer to peer, or
//! bouncing off a relay? This dials the one machine the argument resolves to, runs one probe for a live
//! RTT, then reads the session's best-effort [`conn_info`](bifrost::Session::conn_info) for the path
//! (direct vs relayed) and remote address, and prints one line. The probe is chosen from the peer before
//! the dial: one of your devices (`me/<name>`) is asked for what it serves over `control.services`, which
//! every serving node binds and only your devices reach, so one call gives the reach, the round trip and the
//! list; any other machine (a contact, a key, a link) is asked a measure ping, and `control.services` is
//! never asked of it. The path is read AFTER the probe
//! so iroh's hole-punch has the round trip to land: a session that connects relayed and upgrades reports
//! the upgraded path, not the instant-of-connect one. It reports the current path, which can still be
//! relayed if the upgrade has not completed by then.
//!
//! A bare person (`alice`) reports their one saved machine, and several refuse before anything binds;
//! `alice/macbook` reports that one. Listing the whole tailnet of active sessions (Tailscale's full
//! `status`) needs a long-lived node holding those sessions; that is future work.
//!
//! While `swoosh serve` runs here, the probe is one observed Open through it on its held session to the
//! machine, and the path is read by a Finish after the probe rather than from a session of this run's.

use core::time::Duration;
use std::io::{self, Write};
use std::rc::Rc;

use bifrost::{Discovery, Node, Path, Session, Transport};
use clap::Args;
use measure::{Ping, ProtocolError};
use nauthy::{Link, Service};
use swoosh::contacts::Contacts;
use swoosh::escape::{Escaped, causes};
use swoosh::home::Home;
use swoosh::learn::Admitted;
use swoosh::observation::{Observer, PathSource};
use swoosh::peer::{Kind, Machine, Peer};
use swoosh::reach;
use swoosh::serve::CONTROL_SERVICES_SERVICE;
use swoosh::serve::control_codec::{OpenLane, OpenRefusal, PeerRefusal};
use swoosh::transport::{self, ReachArgs};
use tokio::io::AsyncWriteExt as _;

use crate::commands::machine;
use crate::commands::through_serve::{self, Dial, Routed, Unattached};

pub mod report;

/// Show this machine: its key, lock, root, devices, contacts, links and services.
#[derive(Debug, Args)]
pub struct StatusCmd {
    #[arg(value_name = "machine", help = machine::HELP)]
    pub peer: Option<Peer>,
    /// Print this machine's key and nothing else.
    #[arg(long, conflicts_with = "peer")]
    pub key: bool,
    #[command(flatten)]
    pub reach: ReachArgs,
}

impl swoosh::reaching::Reaching for StatusCmd {
    fn reach_args(&self) -> &swoosh::transport::ReachArgs {
        &self.reach
    }

    /// The peer this verb dials, for the stale-list exchange after it runs.
    fn dialed(&self) -> Option<&swoosh::peer::Peer> {
        self.peer.as_ref()
    }

    fn identity(&self) -> swoosh::identity::Identity {
        self.bind_role().identity()
    }

    /// Dialing, and what it dials as. It reaches a peer and never accepts connections under the
    /// home key, so its bind must not write the key's address record (0.9.0 F1).
    ///
    /// `status` probes one of your devices' member-only `control.services` and any other peer's
    /// family-gated `ping` ([`Probe::of`]), so it presents the member badge rooted at the dialing key (like
    /// `ping`/`speed`). `Family` fuses the identity to `PersistedIfPresent`. A
    /// self-addressing `swoosh:` link-as-peer is threaded INTO the credential so the ONE resolver owns both
    /// slots.
    ///
    /// An `anyone` link typed as the peer presents alone, under a throwaway key (`Credential::dialing`).
    /// The service is read only for a link typed as the peer, and a link's machine is always
    /// [`Kind::Link`], which is pinged: so `ping` is the service here, before the machine resolves, and
    /// the probe itself is picked from the resolved kind.
    fn bind_role(&self) -> swoosh::reaching::BindRole {
        swoosh::reaching::BindRole::Dialing(match &self.peer {
            Some(peer) => swoosh::credential::Credential::dialing(peer, reach::PING_SERVICE),
            None => swoosh::credential::Credential::Family { present: None },
        })
    }

    /// Uniform dispatch: unpack the reach context and run. `status` reads `contacts`, the `transport`
    /// label, and the resolved `present` badge; it ignores `key`.
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
            eyre::bail!("internal: `status` ran without its machine resolved (root-dispatch bug)");
        };
        self.run_status(
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

impl StatusCmd {
    /// Dial the machine, probe the path and a single RTT, and print its status line. An unreachable
    /// machine prints an honest line, and only an answered probe exits green.
    async fn run_status<T: Transport, D: Discovery>(
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
        //
        // A bare `status` splits to `run_local` in the root BEFORE any transport is composed, so a
        // missing peer here is a root-dispatch bug, not a user error.
        let Some(peer) = self.peer else {
            eyre::bail!(
                "internal: `status` reached the reach path without a peer (root-dispatch bug)"
            );
        };
        // Slots 1 and 2 are ALREADY resolved by the composition root's ONE resolver (link-or-badge in
        // slot 1, a fleet badge in slot 2 only for a signet-bound slip); the fold in `bind_role()` routed a
        // link-as-peer through that same resolver, so the verb never threads a slip itself.
        let asked = Probe::of(machine.kind());
        let service: Service = asked.service().parse()?;
        let label = machine.label();
        let line =
            match reach::dial_service(node, machine, &peer, &service, present, membership, bound)
                .await
            {
                // Its first admitted stream tells the composition root it may ask which root vouches for
                // the machine.
                Ok((session, connector)) => {
                    let session = admitted.watch(session, connector);
                    probe_own(&session, asked, &label).await
                }
                Err(_error) => Line::unreachable(label),
            };
        println!("{line}");

        // The composition root closes the node once anything still running beside the verb has ended.
        line.outcome().into_result(&peer, bound)
    }

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
        let Some(peer) = &self.peer else {
            eyre::bail!(
                "internal: `status` reached the reach path without a peer (root-dispatch bug)"
            );
        };
        let Some((socket, connected)) = through_serve::serve(home).await? else {
            return Ok(Routed::OwnBind);
        };
        let asked = Probe::of(machine.kind());
        let service: Service = asked.service().parse()?;
        let mut dial = Dial {
            machine,
            service: &service,
            slip,
            reach: &self.reach,
            contacts,
        };
        // Main: the held session the rest of this home's traffic through `serve` rides to the machine,
        // so the path is the one that traffic gets.
        let socket = Rc::new(socket);
        let (session, observer) = match dial.observed(&socket, connected, OpenLane::Main).await {
            Ok(opened) => opened,
            Err(Unattached::Refused(refusal)) => match own_line(&machine.label(), asked, refusal) {
                Ok(line) => {
                    writeln!(io::stdout(), "{line}")?;
                    return Ok(Routed::Ran(line.outcome().unbound_result(peer)));
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
        let ended = observed(
            &session,
            observer,
            asked,
            &machine.label(),
            peer,
            async || dial.stopped(&socket).await,
            &mut io::stdout(),
            &mut io::stderr(),
        )
        .await;
        Ok(Routed::Ran(ended))
    }

    /// The bare (no-peer) path: this machine, from its own files. Runs BEFORE any transport is composed
    /// (dispatched locally in the root), so a bare `swoosh status` never binds an endpoint and never dials.
    /// A reach flag typed on it is refused in the root, which alone can tell it from its variable.
    pub async fn run_local(self, home: &Home) -> eyre::Result<()> {
        let print = if self.key {
            report::Print::Key
        } else {
            report::Print::Report
        };
        report::run(home, print).await
    }
}

/// What `status` asks a reached device, chosen from the resolved machine's kind before the dial.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Probe {
    /// One of your devices: `control.services`, for the reach, the round trip and what it serves.
    Services,
    /// Any other machine: a measure ping.
    Ping,
}

impl Probe {
    /// The probe for a machine of `kind`: only your devices are asked `control.services`, however they
    /// were typed (a name or a key), since the kind is read from the book; a contact's machine, a key no
    /// name holds, or a link is pinged.
    fn of(kind: Kind) -> Self {
        match kind {
            Kind::Yours => Self::Services,
            Kind::Link | Kind::Contact | Kind::Key => Self::Ping,
        }
    }

    /// The service this probe dials.
    fn service(self) -> &'static str {
        match self {
            Self::Services => CONTROL_SERVICES_SERVICE,
            Self::Ping => reach::PING_SERVICE,
        }
    }
}

/// Probe a session this run bound itself, and read the path after the probe from that session.
async fn probe_own<S: Session>(session: &S, asked: Probe, label: &str) -> Line {
    match probe(session, asked, label).await {
        Ok(answered) => answered.line(label, Some(session.conn_info().path)),
        Err(line) => line,
    }
}

/// The probe over `session`, one stream through `serve`, beside `observer`, printing on `out` and `err`.
/// An answered probe is Finished and then printed, its path the Finish's, or no path and a warning when
/// that reading fails; the round trip is always the probe's own. A probe that did not answer prints its
/// line and its error first, and is Finished after. Before a probe that broke blames the machine,
/// `stopped` asks whether `serve` itself went: then its line stands alone, with nothing on stdout.
#[expect(
    clippy::too_many_arguments,
    reason = "the probe, its observer and the lines it prints to"
)]
async fn observed<P: PathSource, S: Session>(
    session: &S,
    mut observer: Observer<P>,
    asked: Probe,
    label: &str,
    peer: &Peer,
    stopped: impl AsyncFnOnce() -> Option<eyre::Report>,
    out: &mut impl Write,
    err: &mut impl Write,
) -> eyre::Result<()> {
    let probed = tokio::select! {
        probed = probe(session, asked, label) => probed,
        never = observer.watch() => match never {},
    };
    let answered = match probed {
        Ok(answered) => answered,
        Err(line) => {
            // A broken probe asks whether `serve` went first: then the machine is not to blame. A
            // refusal skips the ask, since `serve` relayed the machine's answer.
            if line.outcome() == reach::Outcome::Failed
                && let Some(gone) = stopped().await
            {
                return Err(through_serve::failed(gone, observer, err).await);
            }
            writeln!(out, "{line}")?;
            return through_serve::ended(line.outcome().unbound_result(peer), observer, err).await;
        }
    };
    let path = through_serve::final_path(observer.finish().await, err)?;
    writeln!(out, "{}", answered.line(label, path.map(|info| info.path)))?;
    Ok(())
}

/// The line `status` prints for an Open through `serve` the resident refused, where the own bind prints
/// its own line for the same outcome; the refusal back where the line is the resident's (its cap, an
/// ended standing, this machine). A timeout reads `unreachable`: the resident cannot say whether the
/// dial or the stream timed out, and `unreachable` never claims a reach that did not happen.
fn own_line(label: &str, asked: Probe, refusal: OpenRefusal) -> Result<Line, OpenRefusal> {
    match refusal {
        OpenRefusal::Unreachable(detail) => {
            tracing::debug!(%detail, "serve did not reach the machine");
            Ok(Line::unreachable(label.to_owned()))
        }
        OpenRefusal::Timeout => {
            tracing::debug!("serve's open to the machine timed out");
            Ok(Line::unreachable(label.to_owned()))
        }
        OpenRefusal::Peer(PeerRefusal::NotAdmitted) => {
            Ok(Line::refused(label, Refused::NotAdmitted(asked)))
        }
        OpenRefusal::Peer(peer) => Ok(Line::refused(
            label,
            Refused::Other(bifrost::Refusal::from(peer).to_string()),
        )),
        OpenRefusal::Broken(detail) | OpenRefusal::PeerUnreadable(detail) => {
            Ok(Line::failed(label, detail.to_string()))
        }
        OpenRefusal::Busy | OpenRefusal::StandingEnded | OpenRefusal::NotHere => Err(refusal),
    }
}

/// What a reached device's answer measured, before its path is read: the probe's own round trip, and,
/// from one of your devices, what it serves. The path is the caller's to read, since only the caller
/// knows which reading belongs to this probe.
struct Answered {
    rtt: Duration,
    serving: Option<Vec<String>>,
}

impl Answered {
    /// The line for this answer under `label`, with `path` as the caller read it after the probe, or
    /// none when that reading failed.
    fn line(self, label: &str, path: Option<Path>) -> Line {
        Line {
            label: label.to_owned(),
            state: State::Reached {
                path,
                rtt: self.rtt,
                serving: self.serving,
            },
        }
    }
}

/// Ask a reached session the probe `asked` and measure the answer, or the line for a probe that did not
/// answer, under `label` (the machine as the user named it, matching `ping`).
async fn probe<S: Session>(session: &S, asked: Probe, label: &str) -> Result<Answered, Line> {
    match asked {
        Probe::Ping => probe_ping(session, label).await,
        Probe::Services => probe_services(session, label).await,
    }
}

/// Ask one of your reached devices what it serves: the one `control.services` read gives the round trip
/// (the request out, the list back, timed here) and the list. The node's own dotted routes are left out
/// of the list.
async fn probe_services<S: Session>(session: &S, label: &str) -> Result<Answered, Line> {
    let asked = tokio::time::Instant::now();
    let (mut writer, reader) = match session.open_bi().await {
        Ok(halves) => halves,
        Err(bifrost::Error::Refused(refusal)) => {
            let refused = match refusal {
                bifrost::Refusal::NotAdmitted => Refused::NotAdmitted(Probe::Services),
                other => Refused::Other(other.to_string()),
            };
            return Err(Line::refused(label, refused));
        }
        Err(error) => return Err(Line::failed(label, causes(&error))),
    };
    // The read sends nothing; ending the write half lets the node's reply complete. Ended, not dropped:
    // through `serve` a half dropped unended reaches the node as a reset.
    if let Err(error) = writer.shutdown().await {
        return Err(Line::failed(label, causes(&error)));
    }
    let catalog = match reach::read_catalog(reader).await {
        Ok(catalog) => catalog,
        Err(error) => return Err(Line::failed(label, format!("{error:#}"))),
    };
    let rtt = asked.elapsed();
    let serving = catalog
        .entries()
        .filter(|entry| !entry.name.contains('.'))
        .map(|entry| entry.name.clone())
        .collect();
    Ok(Answered {
        rtt,
        serving: Some(serving),
    })
}

/// Ping one reached session once for a live round trip.
async fn probe_ping<S: Session>(session: &S, label: &str) -> Result<Answered, Line> {
    // A single measure ping for a fresh, honest RTT, measured the same way on every session.
    let probed = Ping {
        count: 1,
        interval: Duration::ZERO,
    }
    .run(session)
    .await;

    // NO probe error is a healthy line with a borrowed transport RTT. A peer that took the dial and then
    // failed still has a live path and a path RTT, so `.ok()`-swallowing the error would print
    // `direct to <addr>, rtt ...`: a full-health line for a peer that never answered. Every failure gets
    // its own state instead, the refusal named apart from the rest because "it does not serve ping" is a
    // different fact from "the exchange broke".
    let report = match probed {
        Ok(report) => report,
        Err(ProtocolError::Refused(refusal)) => {
            let refused = match refusal {
                measure::Refusal::Stream(bifrost::Refusal::NotAdmitted) => {
                    Refused::NotAdmitted(Probe::Ping)
                }
                other => Refused::Other(other.to_string()),
            };
            return Err(Line::refused(label, refused));
        }
        Err(error) => return Err(Line::failed(label, causes(&error))),
    };

    // A report can come back with nothing in it: the engine folds a broken exchange into LOSS rather than
    // an error, so the typed-error arm above catches only what escapes that. Zero received is zero
    // measurements, and the transport's own estimate is not a measurement of this probe, so the round
    // trip is the probe's own average or there is none: a reading of the connection (the session's, or
    // the report `serve` gave as the stream attached) never stands in for it.
    let Some(rtt) = report.avg() else {
        return Err(Line::unanswered(label, report.sent()));
    };
    Ok(Answered { rtt, serving: None })
}

/// A rendered status line for one device: reachable (path + RTT), unreachable, reached-but-refused, or
/// reached-but-the-probe-failed.
struct Line {
    /// The device as the user named it, or the reached key's short form.
    label: String,
    state: State,
}

/// The outcome for one device. Every way a probe can fail is a first-class state, distinct from both
/// reachable and unreachable: a node that answered the dial and then refused (or broke) is neither a
/// healthy path line nor an "unreachable". Making each its own variant is what stops a failure from
/// rendering as a healthy line with a borrowed transport RTT.
enum State {
    /// The device answered the probe: the path read after the probe, unless that reading failed, the
    /// probe's own RTT, and, from one of your devices, what it serves.
    Reached {
        path: Option<Path>,
        rtt: Duration,
        serving: Option<Vec<String>>,
    },
    /// The device did not answer the dial at all.
    Unreachable,
    /// The device answered but refused the probe.
    Refused { refused: Refused },
    /// The device answered the dial and the probe then failed: the stream never opened, the exchange
    /// broke, or the peer refused with a code this client cannot read. Carries the cause chain, as the
    /// peer's text may be in it. Its own state, not a `Reached` line with the transport's RTT: nothing
    /// answered the probe, so there is no measurement and no health to report.
    Failed { cause: String },
    /// The exchange completed and nothing came back. The engine folds a broken exchange into LOSS and
    /// returns a report rather than an error, so this is the shape most mid-probe failures actually take,
    /// and the typed-error arm above catches only the few that escape it. Zero received is zero
    /// measurements, so there is no round trip to report and the transport's own estimate is not one:
    /// borrowing it here is exactly how a broken peer printed a healthy line.
    Unanswered { sent: u32 },
}

/// Why a reached device refused the probe. Only the access refusal is reworded, and it claims no more than
/// the reply says; every other refusal (busy, rate-limited, a bad request, a method the service does not
/// serve) prints the peer's own text.
enum Refused {
    /// The gate did not admit this machine to the probe's service.
    NotAdmitted(Probe),
    /// Any other refusal, as the peer gave it.
    Other(String),
}

impl Line {
    fn unreachable(label: String) -> Self {
        Self {
            label,
            state: State::Unreachable,
        }
    }

    fn refused(label: &str, refused: Refused) -> Self {
        Self {
            label: label.to_owned(),
            state: State::Refused { refused },
        }
    }

    fn failed(label: &str, cause: String) -> Self {
        Self {
            label: label.to_owned(),
            state: State::Failed { cause },
        }
    }

    fn unanswered(label: &str, sent: u32) -> Self {
        Self {
            label: label.to_owned(),
            state: State::Unanswered { sent },
        }
    }

    /// How far this device got, for the exit code and final error. Exhaustive on purpose: a new
    /// [`State`] cannot compile until it names its rank, so no device state can drift into the green the
    /// way an unset `any_healthy` flag once let it.
    fn outcome(&self) -> reach::Outcome {
        match self.state {
            State::Reached { .. } => reach::Outcome::Healthy,
            State::Unreachable => reach::Outcome::Unreachable,
            State::Refused { .. } => reach::Outcome::Refused,
            State::Failed { .. } => reach::Outcome::Failed,
            State::Unanswered { .. } => reach::Outcome::Failed,
        }
    }
}

impl core::fmt::Display for Line {
    /// `<peer>, path: <direct | relayed through <relay>>, rtt <n>`, Tailscale-status shaped, with no
    /// `path:` when the reading after the probe failed, or `<peer>: unreachable` for a device that did
    /// not answer, or `reached, but refused (<refusal>)` / `reached, but the probe failed (<cause>)` for a
    /// node that answered the dial and then said no or broke. Both failure lines say it was REACHED (not
    /// unreachable) and render their typed cause, so a gate refusal reads descriptively and is never
    /// doubled (`refused (refused)`), and a mid-protocol failure names what broke instead of a
    /// healthy-looking path. The path is the one `ping` and `speed` print. No line names the transport:
    /// through `serve` the verb does not know which one carried the probe.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // A reached device's line carries its fields after a comma, not a colon.
        let separator = match self.state {
            State::Reached { .. } => ",",
            _ => ":",
        };
        write!(f, "{}{separator} ", self.label)?;
        match &self.state {
            State::Unreachable => f.write_str("unreachable"),
            // The refusal and the cause chain carry the peer's text, so both print through the escaper.
            State::Refused {
                refused: Refused::NotAdmitted(Probe::Services),
            } => {
                let device = self.label.strip_prefix("me/").unwrap_or(&self.label);
                write!(
                    f,
                    "reached, but {device} does not count this machine as one of your devices"
                )
            }
            // A refused ping cannot tell "does not serve ping" from "will not admit you", so the line
            // claims neither.
            State::Refused {
                refused: Refused::NotAdmitted(Probe::Ping),
            } => f.write_str("reached, but it does not answer ping for you"),
            State::Refused {
                refused: Refused::Other(text),
            } => write!(f, "reached, but refused ({})", Escaped(text)),
            State::Failed { cause } => {
                write!(f, "reached, but the probe failed ({})", Escaped(cause))
            }
            State::Unanswered { sent } => {
                write!(
                    f,
                    "reached, but the probe went unanswered ({sent} sent, 0 back)"
                )
            }
            State::Reached { path, rtt, serving } => {
                if let Some(path) = path {
                    write!(f, "path: {}, ", reach::PathLine(path))?;
                }
                write!(f, "rtt {:.3} ms", rtt.as_secs_f64() * 1000.0)?;
                // The names are the device's own, so they print through the escaper.
                match serving.as_deref() {
                    None => Ok(()),
                    Some([]) => f.write_str("; serving: nothing"),
                    Some(names) => {
                        let names: Vec<String> =
                            names.iter().map(|name| Escaped(name).to_string()).collect();
                        write!(f, "; serving: {}", names.join(", "))
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use bifrost::{ConnInfo, NodeId, Path, PathChanges, Session};
    use clap::Parser as _;
    use swoosh::peer::Kind;
    use swoosh::testkit::TestWrite;
    use swoosh::{reach, transport};

    use super::{Answered, Line, Probe, Refused, probe_own};
    use crate::commands::serve::humanize_secs;

    /// Uptimes and idle ages render as the coarsest two units, so a status reads at a glance. The
    /// formatter is shared with the serve banner (`humanize_secs`), so this pins the shape once.
    #[test]
    fn uptime_spans_render_coarsest_two_units() {
        assert_eq!(humanize_secs(0), "0s");
        assert_eq!(humanize_secs(45), "45s");
        assert_eq!(humanize_secs(90), "1m 30s");
        assert_eq!(humanize_secs(2 * 3600 + 14 * 60), "2h 14m");
        assert_eq!(humanize_secs(3 * 86_400 + 5 * 3600), "3d 5h");
    }

    /// A session that answered the dial and then broke: the handshake landed, so it reports a live direct
    /// path WITH the transport's own round-trip estimate, but no probe stream ever opens. This is the
    /// shape a peer takes when it dies (or its service task panics) between the handshake and the first
    /// stream, and the exact shape that used to render as a fully healthy status line.
    struct BrokenSession;

    impl BrokenSession {
        /// The remote the live path reaches: it must never appear on a line for a probe that failed.
        const REMOTE: &'static str = "203.0.113.7:41641";
    }

    impl Session for BrokenSession {
        type Write = TestWrite<tokio::io::DuplexStream>;
        type Read = tokio::io::DuplexStream;

        fn peer(&self) -> NodeId {
            NodeId::from_ed25519_secret(&[3u8; 32])
        }

        async fn open_bi(&self) -> Result<(Self::Write, Self::Read), bifrost::Error> {
            Err(bifrost::Error::Stream("peer went away".into()))
        }

        async fn accept_bi(&self) -> Result<(Self::Write, Self::Read), bifrost::Error> {
            Err(bifrost::Error::Closed)
        }

        async fn wait_closed(&self) {}

        /// A double that carries nothing has nothing to end.
        fn close(&self) {}

        /// The path `conn_info` reports, once.
        fn path_changes(&self) -> PathChanges {
            PathChanges::fixed(self.conn_info().path)
        }

        fn conn_info(&self) -> ConnInfo {
            ConnInfo {
                path: Path::Direct,
                rtt: Some(core::time::Duration::from_millis(12)),
                remote: Some(Self::REMOTE.parse().expect("a valid addr")),
            }
        }
    }

    /// A session whose probe stream OPENS and then answers nothing: writes are swallowed and the reply
    /// read is an immediate end-of-stream. That is what a peer looks like when its service task dies after
    /// accepting the stream, and it is the COMMON shape of a mid-probe failure, because the engine folds a
    /// broken exchange into loss and returns a report rather than an error. The typed-error arm never sees
    /// it.
    struct SilentSession;

    impl SilentSession {
        /// The remote the live path reaches: it must never appear on a line for an unanswered probe.
        const REMOTE: &'static str = "203.0.113.9:41641";
    }

    impl Session for SilentSession {
        /// Swallows the request and the closing shutdown, so neither surfaces as a typed error and the
        /// run reaches the empty-report path this fixture exists to exercise.
        type Write = TestWrite<tokio::io::Sink>;
        /// End-of-stream on the first read: the reply never comes.
        type Read = tokio::io::Empty;

        fn peer(&self) -> NodeId {
            NodeId::from_ed25519_secret(&[4u8; 32])
        }

        async fn open_bi(&self) -> Result<(Self::Write, Self::Read), bifrost::Error> {
            Ok((tokio::io::sink().into(), tokio::io::empty()))
        }

        async fn accept_bi(&self) -> Result<(Self::Write, Self::Read), bifrost::Error> {
            Err(bifrost::Error::Closed)
        }

        async fn wait_closed(&self) {}

        /// A double that carries nothing has nothing to end.
        fn close(&self) {}

        /// The path `conn_info` reports, once.
        fn path_changes(&self) -> PathChanges {
            PathChanges::fixed(self.conn_info().path)
        }

        fn conn_info(&self) -> ConnInfo {
            ConnInfo {
                path: Path::Direct,
                rtt: Some(core::time::Duration::from_millis(9)),
                remote: Some(Self::REMOTE.parse().expect("a valid addr")),
            }
        }
    }

    /// The case the typed-error arm does NOT reach, and the one a real broken peer usually takes. The
    /// engine treats a broken exchange as a LOST probe and returns an empty report, so `status` gets an
    /// `Ok` with nothing measured. Reading the transport's own round-trip estimate there prints a fully
    /// healthy line, with an address, for a peer that answered nothing.
    #[tokio::test]
    async fn a_probe_with_nothing_back_is_never_a_healthy_line() {
        let line = probe_own(&SilentSession, Probe::Ping, "alice/nas").await;
        let text = line.to_string();

        assert!(
            text.contains("reached, but the probe went unanswered"),
            "an empty report says the node was reached and the probe was not answered: {text}"
        );
        assert!(
            !text.contains("rtt") && !text.contains("direct"),
            "the transport's own estimate is not a measurement of this probe: {text}"
        );
        assert!(
            !text.contains(SilentSession::REMOTE),
            "an unanswered probe renders no address, matching the other two failure lines: {text}"
        );
        assert_eq!(
            line.outcome(),
            reach::Outcome::Failed,
            "an unanswered probe is not healthy: {text}"
        );
        assert!(
            line.outcome().into_result(&"alice", &bound()).is_err(),
            "an unanswered probe exits non-zero: {text}"
        );
    }

    /// A probe that fails after the dial is REACHED-but-broken, never a healthy line: it must not borrow
    /// the transport's own path RTT and render `direct to <addr>, rtt ...` for an exchange that never
    /// answered, and it must not hold the exit code green. Without its own state this printed a
    /// perfect status line for a peer that had just died.
    #[tokio::test]
    async fn a_probe_that_failed_after_the_dial_is_never_a_healthy_line() {
        let line = probe_own(&BrokenSession, Probe::Ping, "alice/macbook").await;
        let text = line.to_string();

        assert!(
            text.contains("reached, but the probe failed"),
            "a broken probe says what happened, and that the node WAS reached: {text}"
        );
        assert!(
            text.contains("stream"),
            "the typed cause chain is rendered, not swallowed: {text}"
        );
        assert!(
            !text.contains("rtt") && !text.contains("direct"),
            "no borrowed path RTT and no healthy path phrase for a probe that never answered: {text}"
        );
        assert!(
            !text.contains(BrokenSession::REMOTE),
            "a failed probe renders no address, matching the refused line: {text}"
        );
        assert_eq!(
            line.outcome(),
            reach::Outcome::Failed,
            "a failed probe is its own outcome: {text}"
        );
        assert!(
            line.outcome().into_result(&"alice", &bound()).is_err(),
            "a failed probe exits non-zero: {text}"
        );
    }

    /// The bind every outcome assertion here is made under: the default iroh reach, so no
    /// transport remedy line joins the message.
    fn bound() -> transport::Bound {
        transport::Bound {
            local: false,
            reach: transport::Reach::default(),
        }
    }

    /// `status <machine>` prints the one path carrying bytes on its line: `direct`, or `relayed through`
    /// the relay's host alone, through the escaper and without iroh's root dot, so the line never reads
    /// `link., rtt`. A direct path with a standby relay is `Direct` in bifrost's report, so it never reads
    /// as relayed.
    #[test]
    fn status_machine_prints_the_path_carrying_bytes() {
        let rtt = core::time::Duration::from_millis(12);
        let line = |path| {
            Answered { rtt, serving: None }
                .line("alice/nas", Some(path))
                .to_string()
        };
        let relay = |url: &str| {
            Path::Relayed(bifrost::Relay::from(
                url::Url::parse(url).expect("a relay url"),
            ))
        };
        assert_eq!(line(Path::Direct), "alice/nas, path: direct, rtt 12.000 ms");
        assert_eq!(
            line(relay("https://euw1-1.relay.iroh.network./")),
            "alice/nas, path: relayed through euw1-1.relay.iroh.network, rtt 12.000 ms"
        );
        // A peer can name the relay, so its host prints through the escaper, and nothing else of its URL
        // (no path, no query) reaches the line.
        assert_eq!(
            line(relay("https://relay.example/\u{1b}[2K?ok=1")),
            "alice/nas, path: relayed through relay.example, rtt 12.000 ms"
        );
        // A path that could not be read after the probe leaves the field out, never a dangling comma.
        assert_eq!(
            Answered {
                rtt: core::time::Duration::from_micros(12_031),
                serving: Some(vec!["ssh".to_owned(), "web".to_owned()]),
            }
            .line("me/nas", None)
            .to_string(),
            "me/nas, rtt 12.031 ms; serving: ssh, web"
        );
    }

    /// A session that answers its one stream with `reply`: the bytes of a `control.services` reply, or a
    /// refusal at the stream's open, as a node's gate gives one.
    struct ServicesSession {
        reply: Result<Vec<u8>, bifrost::Refusal>,
    }

    impl Session for ServicesSession {
        type Write = TestWrite<tokio::io::Sink>;
        /// The reply, written whole and its write end closed, so the read ends where the reply does.
        type Read = tokio::io::DuplexStream;

        fn peer(&self) -> NodeId {
            NodeId::from_ed25519_secret(&[5u8; 32])
        }

        async fn open_bi(&self) -> Result<(Self::Write, Self::Read), bifrost::Error> {
            match &self.reply {
                Ok(bytes) => {
                    use tokio::io::AsyncWriteExt as _;

                    let (mut node, read) = tokio::io::duplex(bytes.len().max(1));
                    node.write_all(bytes)
                        .await
                        .map_err(|error| bifrost::Error::Stream(Box::new(error)))?;
                    Ok((tokio::io::sink().into(), read))
                }
                Err(refusal) => Err(bifrost::Error::Refused(refusal.clone())),
            }
        }

        async fn accept_bi(&self) -> Result<(Self::Write, Self::Read), bifrost::Error> {
            Err(bifrost::Error::Closed)
        }

        async fn wait_closed(&self) {}

        /// A double that carries nothing has nothing to end.
        fn close(&self) {}

        fn path_changes(&self) -> PathChanges {
            PathChanges::fixed(self.conn_info().path)
        }

        fn conn_info(&self) -> ConnInfo {
            ConnInfo {
                path: Path::Direct,
                rtt: Some(core::time::Duration::from_millis(12)),
                remote: None,
            }
        }
    }

    /// The `control.services` reply of a node serving `entries`, its own routes included, as `serve`
    /// builds it.
    fn catalog_of(entries: &[&str]) -> Vec<u8> {
        let gate = nauthy::Gate::rooted(
            swoosh::testkit::TestRoot::seeded(7).verify_key(),
            nauthy::Denylist::load(std::env::temp_dir().join("swoosh-status-tests-no-revocations"))
                .expect("an absent denylist loads empty"),
        );
        let mut router = tightbeam::tunnel::Router::new(gate);
        for entry in entries {
            router = swoosh::serve::bind_entry(router, entry, [0u8; 32], &[]).expect("binds");
        }
        router
            .catalog(Some(
                swoosh::serve::CONTROL_SERVICES_SERVICE
                    .parse()
                    .expect("a name"),
            ))
            .encode()
            .expect("a catalog encodes")
    }

    /// `status me/<name>` asks `control.services`, chosen before the dial; a node that serves only one
    /// service answers it with the round trip and its list, a healthy line.
    #[tokio::test]
    async fn status_of_your_device_probes_the_control_route() {
        assert_eq!(Probe::of(Kind::Yours), Probe::Services);
        assert_eq!(Probe::of(Kind::Yours).service(), "control.services");
        let line = probe_own(
            &ServicesSession {
                reply: Ok(catalog_of(&["web=echo:"])),
            },
            Probe::Services,
            "me/nas",
        )
        .await;
        assert_eq!(line.outcome(), reach::Outcome::Healthy);
        let text = line.to_string();
        assert!(text.starts_with("me/nas, path: direct, rtt "), "{text}");
    }

    /// One of your devices' line ends with what it serves, never the node's own routes, and an empty list
    /// reads `nothing`.
    #[tokio::test]
    async fn status_of_your_device_lists_what_it_serves() {
        let line = probe_own(
            &ServicesSession {
                reply: Ok(catalog_of(&["web=echo:"])),
            },
            Probe::Services,
            "me/nas",
        )
        .await
        .to_string();
        assert!(line.ends_with(" ms; serving: web"), "{line}");
        assert!(!line.contains("control."), "no internal route: {line}");

        let empty = probe_own(
            &ServicesSession {
                reply: Ok(catalog_of(&[])),
            },
            Probe::Services,
            "me/nas",
        )
        .await
        .to_string();
        assert!(empty.ends_with(" ms; serving: nothing"), "{empty}");
    }

    /// `status me/nas` through `serve`, over `session`, the Open having attached on a relayed path and the
    /// resident answering the queries with `replies`, `serve` still answering after the probe: what it
    /// printed on stdout, what it did in order (stderr lines and queries), and how it ended.
    async fn through_serve(
        session: &impl Session,
        replies: impl IntoIterator<Item = swoosh::serve::control_codec::PathReply>,
    ) -> (String, Vec<String>, eyre::Result<()>) {
        through_serve_as(session, Probe::Services, replies, None)
            .await
            .0
    }

    /// [`through_serve`] asking `asked`, with `gone` the line `serve` stops with when asked after the
    /// probe, or `None` while it answers, and whether it was asked.
    async fn through_serve_as(
        session: &impl Session,
        asked: Probe,
        replies: impl IntoIterator<Item = swoosh::serve::control_codec::PathReply>,
        gone: Option<&str>,
    ) -> ((String, Vec<String>, eyre::Result<()>), bool) {
        use crate::commands::through_serve::tests::{Events, reading, relayed};

        let events = Events::answering(replies);
        let mut out = Vec::new();
        let was_asked = core::cell::Cell::new(false);
        let ended = super::observed(
            session,
            events.observer(reading(relayed())).await,
            asked,
            "me/nas",
            &"me/nas".parse().expect("a machine"),
            async || {
                was_asked.set(true);
                gone.map(|line| eyre::eyre!("{line}"))
            },
            &mut out,
            &mut events.clone(),
        )
        .await;
        (
            (String::from_utf8(out).expect("text"), events.log(), ended),
            was_asked.get(),
        )
    }

    /// A probe that broke through `serve`, or went unanswered, asks whether `serve` went before blaming
    /// the machine: gone, its line stands alone with nothing on stdout; still answering, the machine's
    /// line and its error.
    #[tokio::test(start_paused = true)]
    async fn a_broken_status_through_serve_asks_whether_serve_went() {
        for gone in [true, false] {
            let line = gone.then_some("serve stopped");
            let ((out, log, ended), asked) =
                through_serve_as(&BrokenSession, Probe::Ping, [], line).await;
            assert!(asked);
            assert!(
                ended
                    .expect_err("exit 1")
                    .is::<crate::commands::through_serve::Reported>()
            );
            if gone {
                assert_eq!(out, "");
                assert_eq!(log, ["stderr: error: serve stopped", "Finish"]);
            } else {
                assert_eq!(
                    out,
                    "me/nas: reached, but the probe failed (stream: peer went away)\n"
                );
                assert_eq!(
                    log,
                    [
                        "stderr: error: me/nas: reached, but the probe failed",
                        "Finish"
                    ]
                );
            }
        }
        let ((out, log, _), asked) =
            through_serve_as(&SilentSession, Probe::Ping, [], Some("serve stopped")).await;
        assert!(asked, "an unanswered probe is a broken one");
        assert_eq!(out, "");
        assert_eq!(log, ["stderr: error: serve stopped", "Finish"]);
    }

    /// Through `serve`, an Open the resident refused prints the own bind's line on stdout and its error,
    /// with no reach hint; a timeout reads `unreachable`. The resident's own refusals keep its line.
    #[test]
    fn an_open_refused_through_serve_prints_the_own_binds_line() {
        use swoosh::serve::control_codec::{OpenRefusal, PeerRefusal};

        let detail = || bifrost::RefusalDetail::bounded("busy");
        let peer: super::Peer = "me/nas".parse().expect("a machine");
        for (asked, refusal, line, error) in [
            (
                Probe::Services,
                OpenRefusal::Unreachable(detail()),
                "me/nas: unreachable",
                "could not reach me/nas",
            ),
            (
                Probe::Ping,
                OpenRefusal::Timeout,
                "me/nas: unreachable",
                "could not reach me/nas",
            ),
            (
                Probe::Services,
                OpenRefusal::Peer(PeerRefusal::NotAdmitted),
                "me/nas: reached, but nas does not count this machine as one of your devices",
                "me/nas: reached, but refused",
            ),
            (
                Probe::Ping,
                OpenRefusal::Peer(PeerRefusal::NotAdmitted),
                "me/nas: reached, but it does not answer ping for you",
                "me/nas: reached, but refused",
            ),
            (
                Probe::Ping,
                OpenRefusal::Peer(PeerRefusal::Unavailable(detail())),
                "me/nas: reached, but refused (unavailable: busy)",
                "me/nas: reached, but refused",
            ),
            (
                Probe::Services,
                OpenRefusal::Peer(PeerRefusal::BadRequest(detail())),
                "me/nas: reached, but refused (bad request: busy)",
                "me/nas: reached, but refused",
            ),
            (
                Probe::Services,
                OpenRefusal::Broken(bifrost::RefusalDetail::bounded("reset\r")),
                r"me/nas: reached, but the probe failed (reset\r)",
                "me/nas: reached, but the probe failed",
            ),
            (
                Probe::Ping,
                OpenRefusal::PeerUnreadable(detail()),
                "me/nas: reached, but the probe failed (busy)",
                "me/nas: reached, but the probe failed",
            ),
        ] {
            let printed = super::own_line("me/nas", asked, refusal).expect("the own bind's line");
            assert_eq!(printed.to_string(), line);
            let report = printed.outcome().unbound_result(&peer).expect_err("exit 1");
            assert_eq!(format!("{report:#}"), error);
        }
        for resident in [
            OpenRefusal::Busy,
            OpenRefusal::StandingEnded,
            OpenRefusal::NotHere,
        ] {
            assert!(super::own_line("me/nas", Probe::Services, resident).is_err());
        }
    }

    /// A write half that tells its node it ended, by `shutdown`, and ends nothing when only dropped:
    /// through `serve`, a half dropped unended reaches the node as a reset.
    struct Ending(Option<tokio::sync::oneshot::Sender<()>>);

    impl tokio::io::AsyncWrite for Ending {
        fn poll_write(
            self: core::pin::Pin<&mut Self>,
            _cx: &mut core::task::Context<'_>,
            buf: &[u8],
        ) -> core::task::Poll<std::io::Result<usize>> {
            core::task::Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(
            self: core::pin::Pin<&mut Self>,
            _cx: &mut core::task::Context<'_>,
        ) -> core::task::Poll<std::io::Result<()>> {
            core::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: core::pin::Pin<&mut Self>,
            _cx: &mut core::task::Context<'_>,
        ) -> core::task::Poll<std::io::Result<()>> {
            if let Some(ended) = self.get_mut().0.take() {
                let _ = ended.send(());
            }
            core::task::Poll::Ready(Ok(()))
        }
    }

    /// One of your devices that answers `control.services` only once the request's write half has
    /// ended cleanly, as a node behind `serve` sees it: a half dropped unended is a reset, and the node
    /// answers nothing.
    struct AnswersAnEnd;

    impl Session for AnswersAnEnd {
        type Write = TestWrite<Ending>;
        type Read = tokio::io::DuplexStream;

        fn peer(&self) -> NodeId {
            NodeId::from_ed25519_secret(&[6u8; 32])
        }

        async fn open_bi(&self) -> Result<(Self::Write, Self::Read), bifrost::Error> {
            use tokio::io::AsyncWriteExt as _;

            let (ended, end) = tokio::sync::oneshot::channel();
            let (mut node, read) = tokio::io::duplex(4096);
            let catalog = catalog_of(&["web=echo:"]);
            tokio::spawn(async move {
                if end.await.is_ok() {
                    let _ = node.write_all(&catalog).await;
                }
            });
            Ok((Ending(Some(ended)).into(), read))
        }

        async fn accept_bi(&self) -> Result<(Self::Write, Self::Read), bifrost::Error> {
            Err(bifrost::Error::Closed)
        }

        async fn wait_closed(&self) {}

        fn close(&self) {}

        fn path_changes(&self) -> PathChanges {
            PathChanges::fixed(self.conn_info().path)
        }

        fn conn_info(&self) -> ConnInfo {
            ConnInfo {
                path: Path::Direct,
                ..ConnInfo::default()
            }
        }
    }

    /// The `control.services` probe ends its write half before it reads, on both paths, so a node behind
    /// `serve` reads a clean end rather than a reset and answers.
    #[tokio::test(start_paused = true)]
    async fn the_services_probe_ends_its_write_half_on_both_paths() {
        use swoosh::serve::control_codec::PathReply;

        let own = probe_own(&AnswersAnEnd, Probe::Services, "me/nas").await;
        assert_eq!(
            own.to_string(),
            "me/nas, path: direct, rtt 0.000 ms; serving: web"
        );
        let direct = ConnInfo {
            path: Path::Direct,
            ..ConnInfo::default()
        };
        let (out, _, ended) = through_serve(&AnswersAnEnd, [PathReply::Sample(direct)]).await;
        ended.expect("the device answered");
        assert_eq!(out, "me/nas, path: direct, rtt 0.000 ms; serving: web\n");
    }

    /// Through `serve` the line's path is the Finish's, read after the probe, never the path the stream
    /// attached on, and a probe is Finished as it ends, with no spacing to wait out.
    #[tokio::test(start_paused = true)]
    async fn status_through_serve_prints_the_finishs_path() {
        use swoosh::serve::control_codec::PathReply;

        let answering = ServicesSession {
            reply: Ok(catalog_of(&["web=echo:"])),
        };
        let direct = ConnInfo {
            path: Path::Direct,
            ..ConnInfo::default()
        };
        let (out, log, ended) = through_serve(&answering, [PathReply::Sample(direct)]).await;
        ended.expect("an answered probe exits green");
        assert_eq!(out, "me/nas, path: direct, rtt 0.000 ms; serving: web\n");
        assert_eq!(log, ["Finish"]);
    }

    /// When the reading after the probe fails, the line keeps the probe's own round trip and drops
    /// `path:`, stderr warns once, and the exit stays the probe's.
    #[tokio::test(start_paused = true)]
    async fn status_through_serve_without_a_final_path_warns_and_keeps_its_exit() {
        let answering = ServicesSession {
            reply: Ok(catalog_of(&["web=echo:"])),
        };
        let (out, log, ended) = through_serve(&answering, []).await;
        ended.expect("the probe answered; the missing path does not fail it");
        assert_eq!(out, "me/nas, rtt 0.000 ms; serving: web\n");
        assert_eq!(
            log,
            [
                "Finish",
                "stderr: warning: could not read the path of this run"
            ]
        );
    }

    /// A probe through `serve` that is refused prints its line and its error first, and Finishes its
    /// receipt after, in the run's own task.
    #[tokio::test(start_paused = true)]
    async fn a_refused_status_through_serve_prints_its_error_then_finishes() {
        let refusing = ServicesSession {
            reply: Err(bifrost::Refusal::NotAdmitted),
        };
        let ((out, log, ended), asked) =
            through_serve_as(&refusing, Probe::Services, [], Some("serve stopped")).await;
        assert!(!asked, "a refusal proves serve relayed an answer");
        assert!(
            ended
                .expect_err("a refused probe exits non-zero")
                .is::<crate::commands::through_serve::Reported>()
        );
        assert_eq!(
            out,
            "me/nas: reached, but nas does not count this machine as one of your devices\n"
        );
        assert_eq!(
            log,
            ["stderr: error: me/nas: reached, but refused", "Finish"]
        );
    }

    /// A machine that is not yours (a contact, a key, a link) keeps the ping probe: `control.services` is
    /// never asked of it.
    #[test]
    fn status_of_a_contact_keeps_the_ping_probe() {
        for kind in [Kind::Contact, Kind::Key, Kind::Link] {
            assert_eq!(Probe::of(kind), Probe::Ping, "{kind:?}");
        }
        assert_eq!(Probe::Ping.service(), reach::PING_SERVICE);
    }

    /// One of your devices typed by its key is asked what it serves, as `status me/<name>` is: the probe
    /// is picked from the kind the book gives the key, never from the form typed.
    #[tokio::test]
    async fn status_of_your_devices_key_lists_what_it_serves() {
        use swoosh::testkit::{Script, ScriptedPeer};

        #[derive(clap::Parser)]
        struct Wrap {
            #[command(flatten)]
            status: super::StatusCmd,
        }

        let key = NodeId::from_ed25519_secret(&[0x68; 32]);
        let mut contacts = swoosh::contacts::Contacts::default();
        contacts
            .save(&"me/nas".parse().expect("a device"), key)
            .expect("the name is free");
        let cmd = Wrap::try_parse_from(["x", &key.to_string()])
            .expect("status parses")
            .status;
        let machine = cmd
            .peer
            .as_ref()
            .expect("a machine typed")
            .machine(&contacts)
            .expect("one machine");
        let peer = ScriptedPeer::new(key, [Script::Lists(vec!["web"])]);
        let node = bifrost::Node::new(peer.clone(), bifrost::NoDiscovery);
        let bound = transport::Bound {
            local: false,
            reach: transport::Reach::default(),
        };
        cmd.run_status(
            &node,
            &machine,
            &bound,
            None,
            None,
            swoosh::learn::Admitted::unheard(),
        )
        .await
        .expect("your device answers what it serves");
        let asked: Vec<String> = peer
            .requests()
            .into_iter()
            .map(|request| request.service)
            .collect();
        assert_eq!(asked, ["control.services"]);
    }

    /// On both probes the access refusal prints its own line and no peer text; every other refusal
    /// (busy, a bad request, a method refusal) keeps `reached, but refused (<escaped peer text>)`.
    #[tokio::test]
    async fn status_keeps_other_refusals_as_today() {
        let refused = |refusal: bifrost::Refusal| ServicesSession {
            reply: Err(refusal),
        };
        let mine = probe_own(
            &refused(bifrost::Refusal::NotAdmitted),
            Probe::Services,
            "me/nas",
        )
        .await;
        assert_eq!(mine.outcome(), reach::Outcome::Refused);
        assert_eq!(
            mine.to_string(),
            "me/nas: reached, but nas does not count this machine as one of your devices"
        );
        let theirs = probe_own(
            &refused(bifrost::Refusal::NotAdmitted),
            Probe::Ping,
            "bob/nas",
        )
        .await;
        assert_eq!(
            theirs.to_string(),
            "bob/nas: reached, but it does not answer ping for you"
        );

        let busy = || bifrost::Refusal::Unavailable {
            detail: bifrost::RefusalDetail::bounded("busy"),
        };
        for line in [
            probe_own(&refused(busy()), Probe::Services, "me/nas").await,
            probe_own(&refused(busy()), Probe::Ping, "bob/nas").await,
        ] {
            let line = line.to_string();
            assert!(
                line.ends_with(": reached, but refused (unavailable: busy)"),
                "{line}"
            );
        }
        let method = Line::refused(
            "bob/nas",
            Refused::Other(
                measure::Refusal::Method {
                    code: measure::MethodRefusal::WrongMethod,
                    detail: bifrost::RefusalDetail::bounded("no"),
                }
                .to_string(),
            ),
        )
        .to_string();
        assert!(method.contains(": reached, but refused ("), "{method}");
    }

    /// A peer's refusal detail holding a carriage return, an ESC CSI sequence and a bidi override prints
    /// as escapes on one line, so a node that refused cannot redraw its line as a healthy path.
    #[tokio::test]
    async fn a_hostile_refusal_prints_escaped() {
        let line = probe_own(
            &ServicesSession {
                reply: Err(bifrost::Refusal::BadRequest {
                    detail: bifrost::RefusalDetail::bounded(
                        "no\r\u{1b}[2Kalice/macbook, path: direct\u{202e}",
                    ),
                }),
            },
            Probe::Ping,
            "alice/macbook",
        )
        .await
        .to_string();
        assert_eq!(
            line,
            r"alice/macbook: reached, but refused (bad request: no\r\u{1b}[2Kalice/macbook, path: direct\u{202e})"
        );
        assert!(
            !line.contains(['\r', '\n', '\u{1b}', '\u{202e}']),
            "no raw byte of the peer's reaches the line: {line:?}"
        );
    }
}
