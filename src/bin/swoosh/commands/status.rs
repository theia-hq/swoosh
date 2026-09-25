//! `swoosh status [<peer>]`: report your own node's status, or dial a peer and report the connection
//! path, Tailscale `status` shaped.
//!
//! BARE (`status`, no peer) queries YOUR OWN resident node over the local control socket and prints the
//! public status shape: node id, pid, bound address, uptime, the live service table, and the warm peers.
//! With no resident it teaches (`swoosh serve --resident`) and exits non-zero.
//!
//! With a peer: the single most reassuring thing a p2p tool tells you: am I actually peer to peer, or
//! bouncing off a relay? For each device the peer resolves to, this dials it, runs a single measure ping
//! for a live RTT, then reads the session's best-effort [`conn_info`](bifrost::Session::conn_info) for
//! the path (direct vs relayed) and remote address, and prints one line. The path is read AFTER the probe
//! so iroh's hole-punch has the round trip to land: a session that connects relayed and upgrades reports
//! the upgraded path, not the instant-of-connect one. Over quirk it says direct; over iroh it reports the
//! current path, which can still be relayed if the upgrade has not completed by then.
//!
//! A person (`alice`) fans out to ALL her devices, one status line each, since "how do I reach alice,
//! across her devices" is exactly the diagnostic; `alice/macbook` reports the one. The peer form is
//! one-shot: each named device is dialed in turn. Listing the whole tailnet of active sessions
//! (Tailscale's full `status`) needs a long-lived node holding those sessions; that is future work.

use core::error::Error as _;
use core::time::Duration;

use bifrost::{ConnInfo, Discovery, Node, Path, Session, Transport};
use clap::Args;
use measure::{Ping, ProtocolError, Refusal};
use nauthy::{Link, Service};
use swoosh::contacts::Contacts;
use swoosh::home::Home;
use swoosh::node_client::{ControlClient, NodeClient as _, control_error_report};
use swoosh::peer::Peer;
use swoosh::reach;
use swoosh::serve::control_codec::StatusReply;
use swoosh::transport::{self, ReachArgs};

use crate::commands::serve::humanize_secs;
use crate::commands::service::ls::{disabled_warning, render_catalog};

/// Show your node's status, or a peer's connection path
#[derive(Debug, Args)]
pub struct StatusCmd {
    /// the peer to reach: a petname (`alice`, `alice/desk`), a raw node id, or a `swoosh:` link
    #[arg(value_name = "peer")]
    pub peer: Option<Peer>,
    /// present a `swoosh:` capability link to reach a gated peer
    #[arg(
        long,
        value_name = "link",
        value_parser = swoosh::link::parse,
        long_help = "Optional: your own devices need no link, the dial presents this \
                     device's membership badge. Pass a `swoosh:` link only to reach as a delegate."
    )]
    pub present: Option<Link>,
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

    fn reject_redundant_present(&self) -> eyre::Result<()> {
        match &self.peer {
            Some(peer) => peer.reject_redundant_present(self.present.as_ref()),
            None => Ok(()),
        }
    }

    fn identity(&self) -> swoosh::identity::Identity {
        self.bind_role().identity()
    }

    /// Dialing, and what it dials as. It reaches a peer and never accepts connections under the
    /// home key, so its bind must not write the key's address record (0.9.0 F1).
    ///
    /// `status` probes the peer's family-gated `ping` service, so it presents the member badge rooted at
    /// the dialing key (like `ping`/`speed`). `Family` fuses the identity to `PersistedIfPresent`. The
    /// effective slip is the FOLD of a self-addressing `swoosh:` link-as-peer with an explicit `--present`,
    /// threaded INTO the credential so the ONE resolver owns both slots.
    ///
    /// An `anyone` link typed as the peer presents alone, under a throwaway key (`Credential::dialing`).
    fn bind_role(&self) -> swoosh::reaching::BindRole {
        let present = self.present.clone();
        swoosh::reaching::BindRole::Dialing(match &self.peer {
            Some(peer) => {
                swoosh::credential::Credential::dialing(peer, present, reach::PING_SERVICE)
            }
            None => swoosh::credential::Credential::Family { present },
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
        // The redundant-present conflict is rejected ONCE in the composition root via
        // `Reaching::reject_redundant_present`, before this runs.
        //
        // A bare `status` splits to `run_local` in the root BEFORE any transport is composed, so a
        // missing peer here is a root-dispatch bug, not a user error.
        let Some(peer) = self.peer else {
            eyre::bail!(
                "internal: `status` reached the reach path without a peer (root-dispatch bug)"
            );
        };
        let candidates = reach::candidates(&peer, contacts)?;
        // Slots 1 and 2 are ALREADY resolved by the composition root's ONE resolver (present-or-badge in
        // slot 1, a fleet badge in slot 2 only for a signet-bound slip); the fold in `bind_role()` routed a
        // link-as-peer through that same resolver, so the verb never threads `--present` itself.

        // Report each device, folding how far each one got: the exit code is green only if some device
        // actually answered the probe, so a fan-out where every device was unreachable, refused, or broke
        // mid-probe ends non-zero rather than exiting clean on a screen full of failures. The fold keeps
        // the FURTHEST outcome, which is what the final error names.
        let mut outcome = reach::Outcome::default();
        let service: Service = reach::PING_SERVICE.parse()?;
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
                Ok(session) => probe(&session, &candidate.label, bound.transport).await,
                Err(_error) => Line::unreachable(&candidate.label, bound.transport.name()),
            };
            outcome = outcome.max(line.outcome());
            println!("{line}");
        }

        node.close().await;
        reach::fanout_outcome(outcome, &peer, bound)
    }

    /// The bare (no-peer) path: query YOUR OWN node's status over the local control socket. Runs
    /// BEFORE any transport is composed (dispatched locally in the root), so a bare `swoosh status`
    /// never binds an endpoint it would not use. With no addressable resident the client resolution
    /// teaches the fix (`swoosh serve --resident`) and exits non-zero.
    pub async fn run_local(self, home: &Home) -> eyre::Result<()> {
        // A bare `status` reaches no peer, so an explicit `--present` has nothing to select: refuse it
        // rather than silently dropping it (I.3), before touching the socket.
        swoosh::reaching::reject_bare_present(self.present.as_ref())?;
        // The reach trio binds a transport and seeds discovery for a PEER; a bare `status` binds
        // neither, so the flags are refused by name rather than silently ignored (I.3, B4).
        swoosh::reaching::reject_bare_reach(&self.reach)?;
        let client = ControlClient::resolve(home).map_err(control_error_report)?;
        let status = client.status().await.map_err(control_error_report)?;
        // The disabled-list diagnostic goes to stderr, BEFORE the clean stdout table (I.5): the `?`
        // cells stay on stdout, the reason explaining them rides the diagnostic stream.
        if let Some(warning) = disabled_warning(&status.menu.disabled) {
            eprint!("{warning}");
        }
        print!("{}", render_status(&status));
        Ok(())
    }
}

/// Render the bare self-query status shape: the node id, its pid, the bound address (when the
/// transport hands one out), the uptime, the live service table with disabled markers, and the warm
/// peers. Public shape only: the reply type carries no key material, and nothing here adds any.
fn render_status(status: &StatusReply) -> String {
    let mut out = String::new();
    out.push_str(&format!("node {}\n", status.node_id.short()));
    // The pid directly after the node: `status` is the verb that asks what is running, and the pid is
    // the vocabulary the stop line and the already-resident refusal already name.
    out.push_str(&format!("pid {}\n", status.pid));
    match status.addr {
        Some(addr) => out.push_str(&format!("addr {addr}\n")),
        None => out.push_str("addr none\n"),
    }
    out.push_str(&format!("up {}\n", humanize_secs(status.uptime_secs)));
    out.push_str(&render_catalog(
        &status.menu.catalog,
        Some(&status.menu.disabled),
    ));
    match status.warm.as_slice() {
        [] => out.push_str("warm none\n"),
        entries => {
            let noun = if entries.len() == 1 { "peer" } else { "peers" };
            out.push_str(&format!("warm {} {noun}\n", entries.len()));
            for entry in entries {
                out.push_str(&format!(
                    "  {} idle {}\n",
                    entry.peer.short(),
                    humanize_secs(entry.idle_secs)
                ));
            }
        }
    }
    out
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

    // NO probe error is a healthy line with a borrowed transport RTT. A peer that took the dial and then
    // failed still has a live path and a path RTT, so `.ok()`-swallowing the error would print
    // `direct to <addr>, rtt ...`: a full-health line for a peer that never answered. Every failure gets
    // its own state instead, the refusal named apart from the rest because "it does not serve ping" is a
    // different fact from "the exchange broke".
    let report = match probed {
        Ok(report) => report,
        Err(ProtocolError::Refused(refusal)) => {
            return Line::refused(label.to_owned(), transport.name(), refusal);
        }
        Err(error) => return Line::failed(label.to_owned(), transport.name(), error),
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
    Line::reached(label.to_owned(), transport.name(), initial, info, rtt)
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
    /// The device answered the probe: the path at connect, the path after the probe, and the RTT.
    /// `initial` lets the phrase report a relayed-to-direct upgrade that landed during probing.
    Reached {
        initial: Path,
        info: ConnInfo,
        rtt: Option<Duration>,
    },
    /// The device did not answer the dial at all.
    Unreachable,
    /// The device answered but refused the ping probe (it does not serve ping), carrying the typed refusal.
    Refused { refusal: Refusal },
    /// The device answered the dial and the probe then failed: the stream never opened, the exchange
    /// broke, or the peer refused with a code this client cannot read. Carries the typed cause. Its own
    /// state, not a `Reached` line with the transport's RTT: nothing answered the probe, so there is no
    /// measurement and no health to report.
    Failed { error: ProtocolError },
    /// The exchange completed and nothing came back. The engine folds a broken exchange into LOSS and
    /// returns a report rather than an error, so this is the shape most mid-probe failures actually take,
    /// and the typed-error arm above catches only the few that escape it. Zero received is zero
    /// measurements, so there is no round trip to report and the transport's own estimate is not one:
    /// borrowing it here is exactly how a broken peer printed a healthy line.
    Unanswered { sent: u32 },
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

    fn refused(label: String, transport: &'static str, refusal: Refusal) -> Self {
        Self {
            label,
            transport,
            state: State::Refused { refusal },
        }
    }

    fn failed(label: String, transport: &'static str, error: ProtocolError) -> Self {
        Self {
            label,
            transport,
            state: State::Failed { error },
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
    /// `<peer> via <transport>: <path>[, rtt <n>]`, Tailscale-status shaped, or `<peer> via <transport>:
    /// unreachable` for a device that did not answer, or `reached, but refused (<refusal>)` /
    /// `reached, but the probe failed (<cause>)` for a node that answered the dial and then said no or
    /// broke. Both failure lines say it was REACHED (not unreachable) and render their typed cause, so a
    /// gate refusal reads descriptively and is never doubled (`refused (refused)`), and a mid-protocol
    /// failure names what broke instead of a healthy-looking path. The path phrase (shared with
    /// `ping`/`speed`) names the remote when a direct address is known, and reports a relayed-to-direct
    /// upgrade when one landed.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} via {}: ", self.label, self.transport)?;
        match &self.state {
            State::Unreachable => f.write_str("unreachable"),
            State::Refused { refusal } => write!(f, "reached, but refused ({refusal})"),
            State::Failed { error } => {
                write!(f, "reached, but the probe failed ({})", causes(error))
            }
            State::Unanswered { sent } => {
                write!(
                    f,
                    "reached, but the probe went unanswered ({sent} sent, 0 back)"
                )
            }
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

/// A probe failure's full cause chain, rendered `outer: inner`, the way eyre renders a report for the
/// verbs that can just bail on one. `status` cannot bail (it owes every device a line), so it renders the
/// chain itself: the outer message is routinely the useless half, and `read frame` says nothing a person
/// can act on without the i/o cause underneath it.
fn causes(error: &ProtocolError) -> String {
    let mut chain = error.to_string();
    let mut next = error.source();
    while let Some(cause) = next {
        chain.push_str(": ");
        chain.push_str(&cause.to_string());
        next = cause.source();
    }
    chain
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::{AtomicU32, Ordering};

    use bifrost::{ConnInfo, NodeId, Path, Session};
    use clap::Parser as _;
    use swoosh::home::Home;
    use swoosh::serve::control_codec::{DisabledList, PeerEntry, ServiceMenu, StatusReply};
    use swoosh::{reach, transport};
    use tightbeam::tunnel::ServiceCatalog;

    use super::{Line, probe, render_status};
    use crate::commands::serve::humanize_secs;

    /// Serializes scratch names within this test process; the pid keeps two concurrent runs apart.
    static SCRATCH_SEQ: AtomicU32 = AtomicU32::new(0);

    /// A catalog built from `(name, posture tag)` pairs: the test encodes the production wire form
    /// (0 gated, 1 open) and decodes it through [`ServiceCatalog`].
    fn test_catalog(entries: &[(&str, u8)]) -> ServiceCatalog {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(entries.len() as u32).to_be_bytes());
        for (name, posture) in entries {
            bytes.extend_from_slice(&(name.len() as u16).to_be_bytes());
            bytes.extend_from_slice(name.as_bytes());
            bytes.push(*posture);
        }
        ServiceCatalog::decode(&bytes).expect("the test catalog decodes")
    }

    /// The bare self-query renders the public status shape and nothing else: node id, pid, address,
    /// uptime, the live table, and the warm peers. The exhaustive destructure is the compile-level
    /// guard (Finding 11): a new field on the reply, key material included, fails to compile here
    /// before it can reach a renderer.
    #[test]
    fn bare_status_is_shape_only() {
        let status = StatusReply {
            node_id: NodeId::from_ed25519_secret(&[9u8; 32]),
            pid: 4242,
            addr: Some("127.0.0.1:41641".parse().expect("a valid addr")),
            uptime_secs: 2 * 3600 + 14 * 60,
            menu: ServiceMenu {
                catalog: test_catalog(&[("ping", 0), ("speed", 0)]),
                disabled: DisabledList::Known(vec!["speed".to_owned()]),
            },
            warm: vec![PeerEntry {
                peer: NodeId::from_ed25519_secret(&[7u8; 32]),
                idle_secs: 120,
            }],
        };

        let StatusReply {
            node_id,
            pid,
            addr,
            uptime_secs,
            menu,
            warm,
        } = &status;
        assert_eq!(pid, &4242);
        assert!(addr.is_some(), "the bound address rides the public shape");
        assert_eq!(*uptime_secs, 2 * 3600 + 14 * 60);
        assert_eq!(menu.disabled, DisabledList::Known(vec!["speed".to_owned()]));
        assert_eq!(warm.len(), 1);

        let text = render_status(&status);
        assert!(
            text.contains(&format!("node {}", node_id.short())),
            "{text}"
        );
        assert_eq!(
            text.lines().nth(1),
            Some("pid 4242"),
            "the reply pid renders directly after the node: {text}"
        );
        assert!(text.contains("addr 127.0.0.1:41641"), "{text}");
        assert!(text.contains("up 2h 14m"), "{text}");
        assert!(text.contains("SERVICE") && text.contains("STATE"), "{text}");
        assert!(
            text.lines()
                .any(|line| line.starts_with("speed") && line.contains("off")),
            "the live disabled marker rides the status table: {text}"
        );
        assert!(
            text.lines().any(|line| line == "warm 1 peer"),
            "the warm peer count is a public fact: {text}"
        );
        assert!(text.contains("idle 2m"), "{text}");
        for forbidden in ["secret", "seed", "badge", "private"] {
            assert!(
                !text.contains(forbidden),
                "the shape must not render {forbidden}: {text}"
            );
        }
    }

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

    /// A bare `status` with no addressable resident is the same teaching error as bare `stop`,
    /// non-zero at the root: the self-query never pretends to read a node that is not there.
    #[tokio::test]
    async fn bare_status_without_resident_is_teaching() {
        #[derive(clap::Parser)]
        struct Wrap {
            #[command(flatten)]
            status: super::StatusCmd,
        }

        let seq = SCRATCH_SEQ.fetch_add(1, Ordering::Relaxed);
        let base = std::env::temp_dir().join(format!("sw4-status-{}-{seq}", std::process::id()));
        std::fs::create_dir_all(base.join("home")).expect("scratch home");
        let home = Home::resolve(Some(base.join("home"))).expect("the scratch home resolves");
        let status = Wrap::try_parse_from(["x"])
            .expect("bare status parses")
            .status;

        let error = status
            .run_local(&home)
            .await
            .expect_err("no resident must refuse, never a silent success");
        assert!(
            format!("{error:#}").contains("start one with `swoosh serve --resident`"),
            "the error names the fix: {error:#}"
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    /// A bare `status` reaches no peer, so `--present` has nothing to select: it is refused with the
    /// exact teaching line, never silently dropped (I.3, MAJOR-1).
    #[tokio::test]
    async fn bare_status_rejects_present() {
        #[derive(clap::Parser)]
        struct Wrap {
            #[command(flatten)]
            status: super::StatusCmd,
        }

        let seq = SCRATCH_SEQ.fetch_add(1, Ordering::Relaxed);
        let base =
            std::env::temp_dir().join(format!("sw4-status-present-{}-{seq}", std::process::id()));
        std::fs::create_dir_all(base.join("home")).expect("scratch home");
        let home = Home::resolve(Some(base.join("home"))).expect("the scratch home resolves");
        let link = swoosh::link::Link::from(
            swoosh::testkit::TestRoot::seeded(0xb0)
                .device_badge(
                    swoosh::testkit::TestNode::seeded(0xb1).node_id(),
                    nauthy::Request::expires_in(core::time::Duration::from_secs(300)),
                )
                .expect("mint a stand-in slip"),
        )
        .to_string();
        let status = Wrap::try_parse_from(["x", "--present", &link])
            .expect("bare status --present parses")
            .status;

        let error = status
            .run_local(&home)
            .await
            .expect_err("--present without a peer must refuse, never be ignored");
        assert_eq!(
            format!("{error:#}"),
            "--present only applies when reaching a peer; drop it or name one"
        );

        let _ = std::fs::remove_dir_all(&base);
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

    /// B3: a reached-but-refused line says it was REACHED (distinct from `unreachable`) and renders the
    /// typed refusal descriptively, never echoing a token doubled (`refused (refused)`).
    #[test]
    fn a_reached_but_refused_line_is_descriptive_and_not_doubled() {
        let line = Line::refused(
            "alice/macbook".to_owned(),
            "iroh",
            measure::Refusal::Stream(bifrost::Refusal::NotAdmitted),
        )
        .to_string();
        assert!(
            line.contains("reached, but refused"),
            "a refusal is reached-but-refused, distinct from unreachable: {line}"
        );
        assert!(
            !line.contains("refused (refused)"),
            "the bare token is not doubled: {line}"
        );
        assert!(
            line.contains("not admitted"),
            "the uniform refusal is rendered as a reason a person can act on: {line}"
        );
    }
}
