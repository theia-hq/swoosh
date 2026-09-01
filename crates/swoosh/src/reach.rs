//! Resolve a [`Target`] to a live session: turn a petname or key into a connected peer.
//!
//! The reach-outward verbs share one need: take the peer slot the user typed, resolve it against the
//! contact store, and connect. How they use the resolved set differs, so this module offers two shapes:
//! [`dial`] takes the FIRST device that answers (what `speed` wants, a single-target measurement), and
//! [`connect`] dials ONE named candidate (the primitive `ping` and `status` loop over to fan out across
//! all of a person's devices). Both bound each attempt with [`DIAL_TIMEOUT`] so a wedged device never
//! strands the reachable ones.

use core::time::Duration;

use bifrost::{ConnInfo, Discovery, Node, Path, Transport};
use tightbeam::tunnel::{Connector, ServiceSession};

use crate::contacts::{Candidate, Contacts, Target};
use crate::transport;

/// The two diagnostic services a peer serves, independent so a node may offer one without the other: `ping`
/// (cheap RTT) and `speed` (bandwidth-eating throughput). `ping`/`status` reach [`PING_SERVICE`];
/// `speed` reaches [`SPEED_SERVICE`]. Each verb dials only the service it needs, so a peer that serves only
/// one answers that verb and refuses the other. These are the names `swoosh serve` publishes by default.
pub const PING_SERVICE: &str = "ping";
/// The speed service; see [`PING_SERVICE`].
pub const SPEED_SERVICE: &str = "speed";

/// How long to wait for one candidate device to connect before moving on to the next.
///
/// Weak device-grouping dials a person's devices in order and takes the first that answers, so a single
/// wedged device (a black hole that neither connects nor refuses) must not strand the reachable devices
/// behind it. This bounds each `connect` attempt: a candidate that has not answered within the budget is
/// treated as unreachable and the next is tried, keeping first-reachable actually reachable. Ten seconds
/// is generous for a real handshake (including iroh hole-punching) yet short enough that a dead device
/// does not feel like a hang.
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);

/// A dialed peer: the session plus the label of the device that actually answered.
///
/// The label is returned because a person target can resolve to several devices and this reports WHICH
/// one connected (`alice/macbook`), so a verb prints the device it reached, not the name it was asked
/// for. The reached `NodeId` is available on the session (`Session::peer`) if a caller needs the key.
pub struct Reached<S> {
    /// The live session to the peer.
    pub session: S,
    /// The label the reached device resolved from (`alice/macbook`, or a raw key's short form).
    pub label: String,
}

/// Resolve `target` against `contacts` and connect to the first identity that answers.
///
/// Candidates are tried in resolution order under a per-candidate [`DIAL_TIMEOUT`]; the first successful
/// [`connect`](Node::connect) wins and its error, if all fail, is the last one seen. An unknown petname
/// surfaces the resolver's clean error before any dial. A raw key resolves to a single candidate, so this
/// is a plain dial for the common case and only fans out for a multi-device person. `transport` names the
/// bound backend so the final error can point the user at the fix its transport needs.
pub async fn dial<T: Transport, D: Discovery>(
    node: &Node<T, D>,
    contacts: &Contacts,
    target: &Target,
    transport: transport::Transport,
) -> eyre::Result<Reached<T::Session>> {
    let candidates = target.candidates(contacts)?;

    let mut last_error = None;
    for candidate in candidates {
        match connect(node, &candidate).await {
            Ok(session) => {
                return Ok(Reached {
                    session,
                    label: candidate.label,
                });
            }
            Err(error) => last_error = Some(error),
        }
    }

    // Every candidate failed. `candidates` guarantees at least one, so `last_error` is set; carry its
    // source rather than inventing a message, note the target, and append the fix this transport needs so
    // the user is told what to do next, not just what went wrong.
    let reached = match last_error {
        Some(error) => error.wrap_err(format!("could not reach {target}")),
        None => eyre::eyre!("could not reach {target}: no known device"),
    };
    Err(hint(reached, transport))
}

/// Connect to one named candidate under the [`DIAL_TIMEOUT`], mapping a timeout to a plain unreachable
/// error so a caller loops on to the next device. The primitive `ping` and `status` fan out over: they
/// call this once per device and report each, reachable or not.
pub async fn connect<T: Transport, D: Discovery>(
    node: &Node<T, D>,
    candidate: &Candidate,
) -> eyre::Result<T::Session> {
    // Bound each attempt so a wedged device does not strand the reachable ones behind it: a timeout is
    // just this candidate being unreachable, so it reads as an error like a refused connection would.
    match tokio::time::timeout(DIAL_TIMEOUT, node.connect(candidate.node)).await {
        Ok(Ok(session)) => Ok(session),
        Ok(Err(error)) => {
            tracing::debug!(peer = %candidate.node, %error, "device unreachable");
            Err(eyre::Report::new(error))
        }
        Err(_elapsed) => {
            tracing::debug!(peer = %candidate.node, timeout = ?DIAL_TIMEOUT, "device did not answer in time");
            Err(eyre::eyre!(
                "timed out after {DIAL_TIMEOUT:?} with no response"
            ))
        }
    }
}

/// Resolve `target` to the ordered [`Candidate`]s a fan-out verb reports each of. A thin pass-through to
/// [`Target::candidates`] so a verb resolves without reaching into the contacts module directly.
pub fn candidates(target: &Target, contacts: &Contacts) -> eyre::Result<Vec<Candidate>> {
    Ok(target.candidates(contacts)?)
}

/// A reached peer's GATED measure service: the [`ServiceSession`] to run measure over, plus the label of the
/// device that answered. The session gates every stream it opens through the service request, so measure's
/// `Ping`/`Speedtest` run over it unchanged while each stream is admitted by the peer's family gate.
pub struct Resolved<S> {
    /// The service-scoped session; every `open_bi` speaks the measure service handshake presenting the badge.
    pub session: ServiceSession<S>,
    /// The label the reached device resolved from (`alice/macbook`, or a raw key's short form).
    pub label: String,
}

/// Resolve `target` and open the FIRST reachable device's gated `service` (one of [`PING_SERVICE`] /
/// [`SPEED_SERVICE`]), presenting `present` (the caller's membership badge or an explicit link). What
/// `speed` wants: one target, one session.
///
/// Candidates are tried in resolution order under the per-candidate [`DIAL_TIMEOUT`]; the first whose
/// base session connects wins. The service handshake itself rides each `open_bi` later (the gate is
/// per-stream), so "reachable" here is the underlying connect landing, exactly as the raw [`dial`] meant.
pub async fn dial_service<T: Transport, D: Discovery>(
    node: &Node<T, D>,
    contacts: &Contacts,
    target: &Target,
    service: &str,
    present: Option<String>,
    transport: transport::Transport,
) -> eyre::Result<Resolved<T::Session>> {
    let candidates = target.candidates(contacts)?;

    let mut last_error = None;
    for candidate in candidates {
        match connect_service(node, &candidate, service, present.clone()).await {
            Ok(session) => {
                return Ok(Resolved {
                    session,
                    label: candidate.label,
                });
            }
            Err(error) => last_error = Some(error),
        }
    }

    let reached = match last_error {
        Some(error) => error.wrap_err(format!("could not reach {target}")),
        None => eyre::eyre!("could not reach {target}: no known device"),
    };
    Err(hint(reached, transport))
}

/// Open one named candidate's gated `service` (one of [`PING_SERVICE`] / [`SPEED_SERVICE`]) under the
/// [`DIAL_TIMEOUT`], presenting `present`. The service-scoped session `ping` and `status` loop over to fan
/// out across a person's devices. A timeout maps to a plain unreachable error so a caller loops on to the
/// next device.
pub async fn connect_service<T: Transport, D: Discovery>(
    node: &Node<T, D>,
    candidate: &Candidate,
    service: &str,
    present: Option<String>,
) -> eyre::Result<ServiceSession<T::Session>> {
    let connector = Connector::to_node(candidate.node, service.to_owned(), present);
    // Bound the base connect the same way [`connect`] does, so a wedged device does not strand the
    // reachable ones. The ping/speed handshake rides each stream later, so this bounds only reaching the peer.
    match tokio::time::timeout(DIAL_TIMEOUT, connector.open_service(node)).await {
        Ok(Ok(session)) => Ok(session),
        Ok(Err(error)) => {
            tracing::debug!(peer = %candidate.node, %error, "device unreachable");
            Err(error)
        }
        Err(_elapsed) => {
            tracing::debug!(peer = %candidate.node, timeout = ?DIAL_TIMEOUT, "device did not answer in time");
            Err(eyre::eyre!(
                "timed out after {DIAL_TIMEOUT:?} with no response"
            ))
        }
    }
}

/// Append the fix the bound transport needs to a reach failure, so the error names what to do next.
///
/// Shared by [`dial`] and the fan-out verbs so a `could not reach` over quirk always carries the same
/// remedy, whether a single dial failed or every device in a fan-out did.
pub fn hint(error: eyre::Report, transport: transport::Transport) -> eyre::Report {
    match transport {
        // quirk is direct-only with no discovery, so an unreachable peer is almost always a missing or
        // wrong address hint. Name the exact flag (mirroring the exemplary unknown-contact error) and the
        // one-flag escape to a self-discovering transport.
        transport::Transport::Quirk => error.wrap_err(
            "quirk is direct-only: pass --peer <key>=<addr> (the line the peer's `swoosh serve` printed), or use --transport iroh",
        ),
        transport::Transport::Iroh => error,
    }
}

/// The path phrase for a session's [`ConnInfo`], comparing the path at connect (`initial`) to the path
/// now: `direct to <addr>` / `direct to <addr> (upgraded from relayed)` / `relayed` / `mixed (...)` /
/// `path unknown`. Reports the current state plainly rather than hedging: iroh often connects relayed
/// then hole-punches to direct, so callers sample `initial` at connect and read this after a probe; if
/// the upgrade landed in that window we say so, otherwise we name what it is now. Shared by `status`
/// (its whole output) and `ping`/`speed` (which print it inline so a slow number reads as "it relayed",
/// not a mystery), so all three name a path the same way.
pub fn conn_path(initial: Path, info: &ConnInfo) -> String {
    match info.path {
        Path::Direct => {
            let direct = match info.remote {
                Some(remote) => format!("direct to {remote}"),
                None => "direct".to_owned(),
            };
            // It connected relayed (or mixed) and hole-punching landed a direct path during the probe:
            // report the upgrade, which is the reassuring thing to know actually happened.
            if matches!(initial, Path::Relayed | Path::Mixed) {
                format!("{direct} (upgraded from relayed)")
            } else {
                direct
            }
        }
        // Still relayed after the probe window. Report the current state plainly; a later re-run may
        // show direct if hole-punching completes after this point.
        Path::Relayed => "relayed".to_owned(),
        Path::Mixed => match info.remote {
            Some(remote) => format!("mixed (direct to {remote} and relayed)"),
            None => "mixed (direct and relayed)".to_owned(),
        },
        // The transport does not expose its path (in-process, or not yet instrumented). Say so rather
        // than fabricating a reassuring answer.
        Path::Unknown => "path unknown".to_owned(),
    }
}
