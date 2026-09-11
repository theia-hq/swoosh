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

use core::time::Duration;

use bifrost::{ConnInfo, Discovery, Node, Path, Session, Transport};
use clap::Args;
use measure::{Ping, ProtocolError};
use tightbeam::tunnel;

use crate::commands::serve::control_codec::StatusReply;
use crate::commands::serve::humanize_secs;
use crate::commands::service::ls::{disabled_warning, render_catalog};
use crate::contacts::Contacts;
use crate::home::Home;
use crate::node_client::{ControlClient, NodeClient as _, control_error_report};
use crate::peer::Peer;
use crate::reach;
use crate::transport::{self, ReachArgs};

/// Show your node's status, or a peer's connection path
#[derive(Debug, Args)]
pub struct StatusCmd {
    /// the peer to reach: a petname (`alice`, `alice/desk`), a raw node id, or a `sheer:` link
    #[arg(value_name = "peer")]
    pub peer: Option<Peer>,
    /// present a `sheer:` cap link to a cap-gated peer (a delegate's slip)
    #[arg(
        long,
        value_name = "link",
        long_help = "Optional: your own devices need no link, the dial presents the self-signed \
                     membership badge under this identity. Pass a `sheer:` slip only to reach as a delegate."
    )]
    pub present: Option<crate::credential::SheerLink>,
    #[command(flatten)]
    pub reach: ReachArgs,
}

impl crate::reaching::Reaching for StatusCmd {
    fn reach_args(&self) -> &crate::transport::ReachArgs {
        &self.reach
    }

    /// `status` probes the peer's family-gated `ping` service, so it presents the member badge rooted at
    /// the dialing key (like `ping`/`speed`). `Family` fuses the identity to `PersistedIfPresent`. The
    /// effective slip is the FOLD of a self-addressing `sheer:` link-as-peer with an explicit `--present`,
    /// threaded INTO the credential so the ONE resolver owns both slots.
    fn credential(&self) -> crate::credential::Credential {
        crate::credential::Credential::Family {
            present: self
                .peer
                .as_ref()
                .and_then(Peer::self_present)
                .or_else(|| self.present.clone()),
        }
    }

    fn reject_redundant_present(&self) -> eyre::Result<()> {
        match &self.peer {
            Some(peer) => peer.reject_redundant_present(self.present.as_ref()),
            None => Ok(()),
        }
    }

    fn identity(&self) -> crate::identity::Identity {
        self.credential().identity()
    }

    /// Uniform dispatch: unpack the reach context and run. `status` reads `contacts`, the `transport`
    /// label, and the resolved `present` badge; it ignores `key`.
    async fn run<T: Transport, D: Discovery>(
        self,
        node: &Node<T, D>,
        ctx: crate::reaching::ReachCtx<'_>,
    ) -> eyre::Result<()>
    where
        <T::Session as Session>::Write: Send + 'static,
        <T::Session as Session>::Read: Send + 'static,
    {
        self.run_status(
            node,
            ctx.contacts,
            ctx.transport,
            ctx.present,
            ctx.membership,
        )
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
        transport: transport::Transport,
        present: Option<String>,
        membership: Option<String>,
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
        // slot 1, a fleet badge in slot 2 only for a signet-bound slip); the fold in `credential()` routed a
        // link-as-peer through that same resolver, so the verb never threads `--present` itself.

        // Report each device; track whether any device was HEALTHY (reached and served the probe), so a
        // fan-out where every device was unreachable OR refused ends non-zero rather than exiting clean
        // on a screen full of failures. A refused device answered the dial but does not serve ping, so it
        // is not healthy: it must not hold the exit code green the way a real status line does.
        let mut any_healthy = false;
        let mut any_refused = false;
        for candidate in &candidates {
            let line = match reach::connect_service(
                node,
                candidate,
                reach::PING_SERVICE,
                present.clone(),
                membership.clone(),
            )
            .await
            {
                Ok(session) => probe(&session, &candidate.label, transport).await,
                Err(_error) => Line::unreachable(&candidate.label, transport.name()),
            };
            any_healthy |= line.is_healthy();
            any_refused |= line.is_refused();
            println!("{line}");
        }

        node.close().await;
        reach::fanout_outcome(any_healthy, any_refused, &peer, transport)
    }

    /// The bare (no-peer) path: query YOUR OWN node's status over the local control socket. Runs
    /// BEFORE any transport is composed (dispatched locally in the root), so a bare `swoosh status`
    /// never binds an endpoint it would not use. With no addressable resident the client resolution
    /// teaches the fix (`swoosh serve --resident`) and exits non-zero.
    pub async fn run_local(self, home: &Home) -> eyre::Result<()> {
        // A bare `status` reaches no peer, so an explicit `--present` has nothing to select: refuse it
        // rather than silently dropping it (I.3), before touching the socket.
        crate::reaching::reject_bare_present(self.present.as_ref())?;
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

    /// Whether this device was REACHED but refused the probe (answered the dial, does not serve ping). It
    /// keeps the fan-out non-zero like an unreachable device, but distinguishes a refusal so the final
    /// error is a refusal, not a misleading `could not reach` + transport reach hint.
    fn is_refused(&self) -> bool {
        matches!(self.state, State::Refused { .. })
    }
}

impl core::fmt::Display for Line {
    /// `<peer> via <transport>: <path>[, rtt <n>]`, Tailscale-status shaped, or `<peer> via <transport>:
    /// unreachable` for a device that did not answer, or `<peer> via <transport>: reached, but refused
    /// (<reason>)` for a node that answered but refused the probe. The refused line says it was REACHED (not
    /// unreachable) and renders the reason through `refusal_reason`, so a bare gate refusal reads
    /// descriptively and is never doubled (`refused (refused)`). The path phrase (shared with `ping`/`speed`)
    /// names the remote when a direct address is known, and reports a relayed-to-direct upgrade when one landed.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} via {}: ", self.label, self.transport)?;
        match &self.state {
            State::Unreachable => f.write_str("unreachable"),
            State::Refused { reason } => {
                write!(
                    f,
                    "reached, but refused ({})",
                    tunnel::refusal_reason(reason)
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

#[cfg(test)]
mod tests {
    use core::sync::atomic::{AtomicU32, Ordering};

    use bifrost::NodeId;
    use clap::Parser as _;
    use tightbeam::tunnel::ServiceCatalog;

    use super::{Line, render_status};
    use crate::commands::serve::control_codec::{
        DisabledList, PeerEntry, ServiceMenu, StatusReply,
    };
    use crate::commands::serve::humanize_secs;
    use crate::home::Home;

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
        let link = crate::identity::Secret::ephemeral()
            .member_badge()
            .expect("mint a stand-in slip");
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

    /// B3: a reached-but-refused line says it was REACHED (distinct from `unreachable`) and renders a bare
    /// gate refusal descriptively, never echoing the token doubled (`refused (refused)`).
    #[test]
    fn a_reached_but_refused_line_is_descriptive_and_not_doubled() {
        let line = Line::refused(
            "alice/macbook".to_owned(),
            "iroh",
            tightbeam::tunnel::UNIFORM_REFUSAL.to_owned(),
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
