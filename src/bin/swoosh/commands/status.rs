//! `swoosh status [<peer>]`: what this machine is, or dial a peer and report the connection path,
//! Tailscale `status` shaped.
//!
//! BARE (`status`, no peer) reads this machine's own files and never dials: its key, its lock, its
//! root, its devices, its contacts, the links it shared, and what a running `serve` serves ([`report`]).
//! `--key` prints the key alone.
//!
//! With a peer: the single most reassuring thing a p2p tool tells you: am I actually peer to peer, or
//! bouncing off a relay? For each device the peer resolves to, this dials it, runs one probe for a live
//! RTT, then reads the session's best-effort [`conn_info`](bifrost::Session::conn_info) for the path
//! (direct vs relayed) and remote address, and prints one line. The probe is chosen from the peer before
//! the dial: one of your devices (`me/<name>`) is asked for what it serves over `control.services`, which
//! every serving node binds and only your devices reach, so one call gives the reach, the round trip and the
//! list; any other machine (a contact, a key, a link) is asked a measure ping, and `control.services` is
//! never asked of it. The path is read AFTER the probe
//! so iroh's hole-punch has the round trip to land: a session that connects relayed and upgrades reports
//! the upgraded path, not the instant-of-connect one. Over quirk it says direct; over iroh it reports the
//! current path, which can still be relayed if the upgrade has not completed by then.
//!
//! A person (`alice`) fans out to ALL her devices, one status line each, since "how do I reach alice,
//! across her devices" is exactly the diagnostic; `alice/macbook` reports the one. The peer form is
//! one-shot: each named device is dialed in turn. Listing the whole tailnet of active sessions
//! (Tailscale's full `status`) needs a long-lived node holding those sessions; that is future work.

use core::time::Duration;

use bifrost::{ConnInfo, Discovery, Node, Session, Transport};
use clap::Args;
use measure::{Ping, ProtocolError};
use nauthy::{Link, Service};
use swoosh::contacts::{Contacts, ME};
use swoosh::escape::{Escaped, causes};
use swoosh::home::Home;
use swoosh::peer::Peer;
use swoosh::reach;
use swoosh::serve::CONTROL_SERVICES_SERVICE;
use swoosh::transport::{self, ReachArgs};
use tightbeam::tunnel;
use tokio::io::AsyncReadExt as _;

pub mod report;

/// Show this machine: its key, lock, root, devices, contacts, links and services.
#[derive(Debug, Args)]
pub struct StatusCmd {
    /// the peer to reach: a petname (`alice`, `alice/desk`), a raw node id, or a `swoosh:` link
    #[arg(value_name = "peer")]
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
    fn bind_role(&self) -> swoosh::reaching::BindRole {
        swoosh::reaching::BindRole::Dialing(match &self.peer {
            Some(peer) => swoosh::credential::Credential::dialing(peer, Probe::of(peer).service()),
            None => swoosh::credential::Credential::Family { present: None },
        })
    }

    /// Uniform dispatch: unpack the reach context and run. `status` reads `contacts`, the `transport`
    /// label, and the resolved `present` badge; it ignores `key`.
    async fn run<T: Transport, D: Discovery>(
        self,
        node: &Node<T, D>,
        ctx: swoosh::reaching::ReachCtx<'_>,
    ) -> eyre::Result<()>
    where
        <T::Session as Session>::Write: Send + 'static,
        <T::Session as Session>::Read: Send + 'static,
    {
        self.run_status(node, ctx.contacts, ctx.bound, ctx.present, ctx.membership)
            .await
    }
}

impl StatusCmd {
    /// Resolve the target to its devices, and for each dial, probe the path and a single RTT, and print a
    /// status line. Reports every device (a person fans out); an unreachable one prints an honest line
    /// rather than aborting the rest.
    async fn run_status<T: Transport, D: Discovery>(
        self,
        node: &Node<T, D>,
        contacts: &Contacts,
        bound: &transport::Bound,
        present: Option<Link>,
        membership: Option<Link>,
    ) -> eyre::Result<()> {
        //
        // A bare `status` splits to `run_local` in the root BEFORE any transport is composed, so a
        // missing peer here is a root-dispatch bug, not a user error.
        let Some(peer) = self.peer else {
            eyre::bail!(
                "internal: `status` reached the reach path without a peer (root-dispatch bug)"
            );
        };
        let candidates = reach::candidates(&peer, contacts)?;
        // Slots 1 and 2 are ALREADY resolved by the composition root's ONE resolver (link-or-badge in
        // slot 1, a fleet badge in slot 2 only for a signet-bound slip); the fold in `bind_role()` routed a
        // link-as-peer through that same resolver, so the verb never threads a slip itself.

        // Report each device, folding how far each one got: the exit code is green only if some device
        // actually answered the probe, so a fan-out where every device was unreachable, refused, or broke
        // mid-probe ends non-zero rather than exiting clean on a screen full of failures. The fold keeps
        // the FURTHEST outcome, which is what the final error names.
        let mut outcome = reach::Outcome::default();
        let asked = Probe::of(&peer);
        let service: Service = asked.service().parse()?;
        for candidate in &candidates {
            let line = match reach::connect_service(
                node,
                candidate,
                &service,
                Option::clone(&present),
                Option::clone(&membership),
            )
            .await
            {
                Ok(session) => match asked {
                    Probe::Ping => probe(&session, &candidate.label, bound.transport).await,
                    Probe::Services => {
                        probe_services(&session, &candidate.label, bound.transport).await
                    }
                },
                Err(_error) => Line::unreachable(&candidate.label, bound.transport.name()),
            };
            outcome = outcome.max(line.outcome());
            println!("{line}");
        }

        node.close().await;
        reach::fanout_outcome(outcome, &peer, bound)
    }

    /// The bare (no-peer) path: this machine, from its own files. Runs BEFORE any transport is composed
    /// (dispatched locally in the root), so a bare `swoosh status` never binds an endpoint and never dials.
    pub async fn run_local(self, home: &Home) -> eyre::Result<()> {
        // The reach trio binds a transport and seeds discovery for a PEER; a bare `status` binds
        // neither, so the flags are refused by name rather than silently ignored (I.3, B4).
        swoosh::reaching::reject_bare_reach(&self.reach)?;
        let print = if self.key {
            report::Print::Key
        } else {
            report::Print::Report
        };
        report::run(home, print).await
    }
}

/// What `status` asks a reached device, chosen from the peer before the dial.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Probe {
    /// One of your devices: `control.services`, for the reach, the round trip and what it serves.
    Services,
    /// Any other machine: a measure ping.
    Ping,
}

impl Probe {
    /// The probe for `peer`: `me` or `me/<name>` names your devices, and only those are asked
    /// `control.services`; a contact, a key or a link is pinged.
    fn of(peer: &Peer) -> Self {
        match peer {
            Peer::Named(reference) if reference.petname().as_str() == ME => Self::Services,
            _ => Self::Ping,
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

/// Ask one of your reached devices what it serves: the one `control.services` read gives the round trip
/// (the request out, the list back, timed here) and the list, and the path is read after it, as
/// [`probe`]'s is. The node's own dotted routes are left out of the list.
async fn probe_services<S: Session>(
    session: &S,
    label: &str,
    transport: transport::Transport,
) -> Line {
    let asked = tokio::time::Instant::now();
    let (writer, reader) = match session.open_bi().await {
        Ok(halves) => halves,
        Err(bifrost::Error::Refused(refusal)) => {
            let refused = match refusal {
                bifrost::Refusal::NotAdmitted => Refused::NotAdmitted(Probe::Services),
                other => Refused::Other(other.to_string()),
            };
            return Line::refused(label.to_owned(), transport.name(), refused);
        }
        Err(error) => return Line::failed(label.to_owned(), transport.name(), causes(&error)),
    };
    // The read sends nothing; dropping the write half lets the node's reply complete.
    drop(writer);
    let catalog = match read_catalog(reader).await {
        Ok(catalog) => catalog,
        Err(error) => {
            return Line::failed(label.to_owned(), transport.name(), format!("{error:#}"));
        }
    };
    let rtt = asked.elapsed();
    let serving = catalog
        .entries()
        .filter(|entry| !entry.name.contains('.'))
        .map(|entry| entry.name.clone())
        .collect();
    Line::reached(
        label.to_owned(),
        transport.name(),
        session.conn_info(),
        Some(rtt),
    )
    .serving(serving)
}

/// Read a device's catalog blob under the wire's own bound, then decode it.
///
/// The untrusted end here is the SERVER, which is the direction we do not usually face: these bytes are a
/// remote node's, and an unbounded `read_to_end` lets that node grow this client's buffer for as long as it
/// cares to stream, at 1:1 cost to itself. [`decode`](tunnel::ServiceCatalog::decode)'s own caps cannot
/// help, because by the time it is called the buffer already holds everything the peer sent. So the bound
/// goes on the READ, before the first byte lands, and it is the wire's own
/// [`MAX_CATALOG_BLOB`](tunnel::MAX_CATALOG_BLOB) rather than a number chosen here: the serving end refuses
/// to encode past the same bound, so one number holds both ends of this wire.
///
/// It reads exactly ONE byte past that bound, purely to tell a catalog sitting at the ceiling (legitimate,
/// and decodes) from a peer still streaming (not). Without that byte an over-cap peer would arrive as a
/// truncated-blob decode error, which tells an operator that the list is malformed when what actually
/// happened is that the peer would not stop.
async fn read_catalog(
    reader: impl tokio::io::AsyncRead + Unpin,
) -> eyre::Result<tunnel::ServiceCatalog> {
    let mut bytes = Vec::new();
    reader
        .take(tunnel::MAX_CATALOG_BLOB + 1)
        .read_to_end(&mut bytes)
        .await
        .map_err(|error| eyre::eyre!("{}", causes(&error)))?;
    if bytes.len() as u64 > tunnel::MAX_CATALOG_BLOB {
        eyre::bail!(
            "it sent more than a list of services can be, so the read stopped at {} bytes",
            tunnel::MAX_CATALOG_BLOB
        );
    }
    tunnel::ServiceCatalog::decode(&bytes)
}

/// Probe one reached session for a live RTT and its path, and render its status line under `label` (the
/// device as the user named it, so a fan-out reads by device, matching `ping`).
async fn probe<S: Session>(session: &S, label: &str, transport: transport::Transport) -> Line {
    // A single measure ping for a fresh, honest RTT. Some transports (quirk) carry no rtt estimator, so
    // conn_info().rtt is None there; one probe measures the round trip the same way over any of them.
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
            return Line::refused(label.to_owned(), transport.name(), refused);
        }
        Err(error) => return Line::failed(label.to_owned(), transport.name(), causes(&error)),
    };

    // Read the path AFTER the probe, not before: the round trip gives iroh's hole-punch a moment to
    // land, so a session that starts relayed and upgrades reports "direct" here instead of always
    // showing the pre-upgrade "relayed" it had the instant it connected.
    let info = session.conn_info();
    // A report can come back with nothing in it: the engine folds a broken exchange into LOSS rather than
    // an error, so the typed-error arm above catches only what escapes that. Zero received is zero
    // measurements, and the transport's own estimate is not a measurement of this probe. Falling back to
    // it here is the exact swallow the arm above refuses, one layer down, and it is the common case.
    if report.received() == 0 {
        return Line::unanswered(label.to_owned(), transport.name(), report.sent());
    }
    // The probe answered, so its own round trip is the honest number; the transport's estimate stands in
    // only when a received sample carried no timing.
    let rtt = report.avg().or(info.rtt);
    Line::reached(label.to_owned(), transport.name(), info, rtt)
}

/// A rendered status line for one device: reachable (path + RTT), unreachable, reached-but-refused, or
/// reached-but-the-probe-failed.
struct Line {
    /// The device as the user named it, or the reached key's short form.
    label: String,
    transport: &'static str,
    state: State,
}

/// The outcome for one device. Every way a probe can fail is a first-class state, distinct from both
/// reachable and unreachable: a node that answered the dial and then refused (or broke) is neither a
/// healthy path line nor an "unreachable". Making each its own variant is what stops a failure from
/// rendering as a healthy line with a borrowed transport RTT.
enum State {
    /// The device answered the probe: the path after the probe, the RTT, and, from one of your devices,
    /// what it serves.
    Reached {
        info: ConnInfo,
        rtt: Option<Duration>,
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
    fn reached(
        label: String,
        transport: &'static str,
        info: ConnInfo,
        rtt: Option<Duration>,
    ) -> Self {
        Self {
            label,
            transport,
            state: State::Reached {
                info,
                rtt,
                serving: None,
            },
        }
    }

    /// This reached line with what the device serves appended.
    fn serving(mut self, names: Vec<String>) -> Self {
        if let State::Reached { serving, .. } = &mut self.state {
            *serving = Some(names);
        }
        self
    }

    fn unreachable(label: &str, transport: &'static str) -> Self {
        Self {
            label: label.to_owned(),
            transport,
            state: State::Unreachable,
        }
    }

    fn refused(label: String, transport: &'static str, refused: Refused) -> Self {
        Self {
            label,
            transport,
            state: State::Refused { refused },
        }
    }

    fn failed(label: String, transport: &'static str, cause: String) -> Self {
        Self {
            label,
            transport,
            state: State::Failed { cause },
        }
    }

    fn unanswered(label: String, transport: &'static str, sent: u32) -> Self {
        Self {
            label,
            transport,
            state: State::Unanswered { sent },
        }
    }

    /// How far this device got, for the fan-out's exit code and final error. Exhaustive on purpose: a new
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
    /// `<peer> via <transport>, path: <direct | relayed through <relay>>[, rtt <n>]`, Tailscale-status shaped, or `<peer> via <transport>:
    /// unreachable` for a device that did not answer, or `reached, but refused (<refusal>)` /
    /// `reached, but the probe failed (<cause>)` for a node that answered the dial and then said no or
    /// broke. Both failure lines say it was REACHED (not unreachable) and render their typed cause, so a
    /// gate refusal reads descriptively and is never doubled (`refused (refused)`), and a mid-protocol
    /// failure names what broke instead of a healthy-looking path. The path is the one `ping` and `speed`
    /// print.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // A reached device's line carries `path:` itself, so its separator is a comma, not a second colon.
        let separator = match self.state {
            State::Reached { .. } => ",",
            _ => ":",
        };
        write!(f, "{} via {}{separator} ", self.label, self.transport)?;
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
            State::Reached { info, rtt, serving } => {
                write!(f, "path: {}", reach::conn_path(info))?;
                if let Some(rtt) = rtt {
                    write!(f, ", rtt {:.3} ms", rtt.as_secs_f64() * 1000.0)?;
                }
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
    use core::sync::atomic::{AtomicU32, Ordering};

    use bifrost::{ConnInfo, NodeId, Path, PathChanges, Session};
    use clap::Parser as _;
    use swoosh::home::Home;
    use swoosh::{reach, transport};

    use super::{Line, Probe, Refused, probe, probe_services};
    use crate::commands::serve::humanize_secs;

    /// Serializes scratch names within this test process; the pid keeps two concurrent runs apart.
    static SCRATCH_SEQ: AtomicU32 = AtomicU32::new(0);

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

    /// A bare `status` reaches no peer, so the reach trio (`--transport`/`--local`/`--peer`) has nothing
    /// to bind or find: each is refused by name, never silently ignored (I.3, B4).
    #[tokio::test]
    async fn bare_status_rejects_the_reach_flags() {
        #[derive(clap::Parser)]
        struct Wrap {
            #[command(flatten)]
            status: super::StatusCmd,
        }

        let seq = SCRATCH_SEQ.fetch_add(1, Ordering::Relaxed);
        let base =
            std::env::temp_dir().join(format!("sw4-status-reach-{}-{seq}", std::process::id()));
        std::fs::create_dir_all(base.join("home")).expect("scratch home");
        let home = Home::resolve(Some(base.join("home"))).expect("the scratch home resolves");
        let hint = format!("{}=127.0.0.1:9000", NodeId::from_ed25519_secret(&[5u8; 32]));
        let cases: [(&[&str], &str); 3] = [
            (&["x", "--transport", "quirk"], "--transport"),
            (&["x", "--local"], "--local"),
            (&["x", "--peer", &hint], "--peer"),
        ];
        for (argv, flag) in cases {
            let status = Wrap::try_parse_from(argv)
                .expect("the reach flag parses")
                .status;
            let error = status
                .run_local(&home)
                .await
                .expect_err("no peer, no effect: the flag must refuse, never be ignored");
            assert_eq!(
                format!("{error:#}"),
                format!("{flag} only applies when reaching a peer; drop it or name one")
            );
        }

        let _ = std::fs::remove_dir_all(&base);
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
        type Security = bifrost::InProcess;
        type Write = tokio::io::DuplexStream;
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
        type Security = bifrost::InProcess;
        /// Swallows the request and the closing shutdown, so neither surfaces as a typed error and the
        /// run reaches the empty-report path this fixture exists to exercise.
        type Write = tokio::io::Sink;
        /// End-of-stream on the first read: the reply never comes.
        type Read = tokio::io::Empty;

        fn peer(&self) -> NodeId {
            NodeId::from_ed25519_secret(&[4u8; 32])
        }

        async fn open_bi(&self) -> Result<(Self::Write, Self::Read), bifrost::Error> {
            Ok((tokio::io::sink(), tokio::io::empty()))
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
        let line = probe(&SilentSession, "alice/nas", transport::Transport::Iroh).await;
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
            reach::fanout_outcome(line.outcome(), &"alice", &bound()).is_err(),
            "a fan-out of unanswered probes exits non-zero: {text}"
        );
    }

    /// A probe that fails after the dial is REACHED-but-broken, never a healthy line: it must not borrow
    /// the transport's own path RTT and render `direct to <addr>, rtt ...` for an exchange that never
    /// answered, and it must not hold a fan-out's exit code green. Without its own state this printed a
    /// perfect status line for a peer that had just died.
    #[tokio::test]
    async fn a_probe_that_failed_after_the_dial_is_never_a_healthy_line() {
        let line = probe(&BrokenSession, "alice/macbook", transport::Transport::Iroh).await;
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
            reach::fanout_outcome(line.outcome(), &"alice", &bound()).is_err(),
            "a fan-out of failed probes exits non-zero: {text}"
        );
    }

    /// The bind every fan-out-outcome assertion here is made under: the default iroh reach, so no
    /// transport remedy line joins the message.
    fn bound() -> transport::Bound {
        transport::Bound {
            transport: transport::Transport::Iroh,
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
        let rtt = Some(core::time::Duration::from_millis(12));
        let line = |path| {
            let info = ConnInfo {
                path,
                rtt: None,
                remote: None,
            };
            Line::reached("alice/nas".to_owned(), "iroh", info, rtt).to_string()
        };
        let relay = |url: &str| {
            Path::Relayed(bifrost::Relay::from(
                url::Url::parse(url).expect("a relay url"),
            ))
        };
        assert_eq!(
            line(Path::Direct),
            "alice/nas via iroh, path: direct, rtt 12.000 ms"
        );
        assert_eq!(
            line(relay("https://euw1-1.relay.iroh.network./")),
            "alice/nas via iroh, path: relayed through euw1-1.relay.iroh.network, rtt 12.000 ms"
        );
        // A peer can name the relay, so its host prints through the escaper, and nothing else of its URL
        // (no path, no query) reaches the line.
        assert_eq!(
            line(relay("https://relay.example/\u{1b}[2K?ok=1")),
            "alice/nas via iroh, path: relayed through relay.example, rtt 12.000 ms"
        );
    }

    /// A session that answers its one stream with `reply`: the bytes of a `control.services` reply, or a
    /// refusal at the stream's open, as a node's gate gives one.
    struct ServicesSession {
        reply: Result<Vec<u8>, bifrost::Refusal>,
    }

    impl Session for ServicesSession {
        type Security = bifrost::InProcess;
        type Write = tokio::io::Sink;
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
                    Ok((tokio::io::sink(), read))
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

    /// A peer typed as text, as the command line parses it.
    fn peer(text: &str) -> swoosh::peer::Peer {
        text.parse().expect("a peer")
    }

    /// `status me/<name>` asks `control.services`, chosen before the dial; a node that serves only one
    /// service answers it with the round trip and its list, a healthy line.
    #[tokio::test]
    async fn status_of_your_device_probes_the_control_route() {
        assert_eq!(Probe::of(&peer("me/nas")), Probe::Services);
        assert_eq!(Probe::of(&peer("me")), Probe::Services);
        assert_eq!(Probe::of(&peer("me/nas")).service(), "control.services");
        let line = probe_services(
            &ServicesSession {
                reply: Ok(catalog_of(&["web=echo:"])),
            },
            "me/nas",
            transport::Transport::Iroh,
        )
        .await;
        assert_eq!(line.outcome(), reach::Outcome::Healthy);
        let text = line.to_string();
        assert!(
            text.starts_with("me/nas via iroh, path: direct, rtt "),
            "{text}"
        );
    }

    /// One of your devices' line ends with what it serves, never the node's own routes, and an empty list
    /// reads `nothing`.
    #[tokio::test]
    async fn status_of_your_device_lists_what_it_serves() {
        let line = probe_services(
            &ServicesSession {
                reply: Ok(catalog_of(&["web=echo:"])),
            },
            "me/nas",
            transport::Transport::Iroh,
        )
        .await
        .to_string();
        assert!(line.ends_with(" ms; serving: web"), "{line}");
        assert!(!line.contains("control."), "no internal route: {line}");

        let empty = probe_services(
            &ServicesSession {
                reply: Ok(catalog_of(&[])),
            },
            "me/nas",
            transport::Transport::Iroh,
        )
        .await
        .to_string();
        assert!(empty.ends_with(" ms; serving: nothing"), "{empty}");
    }

    /// A machine that is not yours (a contact, a key, a link) keeps the ping probe: `control.services` is
    /// never asked of it.
    #[test]
    fn status_of_a_contact_keeps_the_ping_probe() {
        let key = NodeId::from_ed25519_secret(&[8u8; 32]).to_string();
        for text in ["bob", "bob/nas", key.as_str()] {
            assert_eq!(Probe::of(&peer(text)), Probe::Ping, "{text}");
        }
        assert_eq!(Probe::Ping.service(), reach::PING_SERVICE);
    }

    /// On both probes the access refusal prints its own line and no peer text; every other refusal
    /// (busy, a bad request, a method refusal) keeps `reached, but refused (<escaped peer text>)`.
    #[tokio::test]
    async fn status_keeps_other_refusals_as_today() {
        let refused = |refusal: bifrost::Refusal| ServicesSession {
            reply: Err(refusal),
        };
        let mine = probe_services(
            &refused(bifrost::Refusal::NotAdmitted),
            "me/nas",
            transport::Transport::Iroh,
        )
        .await;
        assert_eq!(mine.outcome(), reach::Outcome::Refused);
        assert_eq!(
            mine.to_string(),
            "me/nas via iroh: reached, but nas does not count this machine as one of your devices"
        );
        let theirs = probe(
            &refused(bifrost::Refusal::NotAdmitted),
            "bob/nas",
            transport::Transport::Iroh,
        )
        .await;
        assert_eq!(
            theirs.to_string(),
            "bob/nas via iroh: reached, but it does not answer ping for you"
        );

        let busy = || bifrost::Refusal::Unavailable {
            detail: bifrost::RefusalDetail::bounded("busy"),
        };
        for line in [
            probe_services(&refused(busy()), "me/nas", transport::Transport::Iroh).await,
            probe(&refused(busy()), "bob/nas", transport::Transport::Iroh).await,
        ] {
            let line = line.to_string();
            assert!(
                line.ends_with(": reached, but refused (unavailable: busy)"),
                "{line}"
            );
        }
        let method = Line::refused(
            "bob/nas".to_owned(),
            "iroh",
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
        let line = probe(
            &ServicesSession {
                reply: Err(bifrost::Refusal::BadRequest {
                    detail: bifrost::RefusalDetail::bounded(
                        "no\r\u{1b}[2Kalice/macbook via iroh, path: direct\u{202e}",
                    ),
                }),
            },
            "alice/macbook",
            transport::Transport::Iroh,
        )
        .await
        .to_string();
        assert_eq!(
            line,
            r"alice/macbook via iroh: reached, but refused (bad request: no\r\u{1b}[2Kalice/macbook via iroh, path: direct\u{202e})"
        );
        assert!(
            !line.contains(['\r', '\n', '\u{1b}', '\u{202e}']),
            "no raw byte of the peer's reaches the line: {line:?}"
        );
    }
}
