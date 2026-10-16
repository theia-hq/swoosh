//! Reach a resolved [`Machine`]: one dial, bounded, and the one follow-up a refused dial to one of your
//! own devices makes to learn why.
//!
//! A verb resolves its peer to exactly one machine before anything binds ([`Peer::machine`]), so every
//! reach here dials one key. [`dial`] connects for a verb that drives the raw session; [`dial_service`]
//! connects for one whose every stream is gated through one service request, handing back the connector
//! beside the session. Both bound the attempt with [`DIAL_TIMEOUT`], so a wedged machine reads as
//! unreachable rather than as a hang.
//!
//! [`Peer::machine`]: crate::peer::Peer::machine

use core::time::Duration;

use bifrost::{ConnInfo, Discovery, Node, NodeId, Path, Session, Transport};
use nauthy::{Link, Service};
use tightbeam::tunnel::{self, Connector};
use tokio::io::AsyncReadExt as _;

use crate::escape::{Escaped, causes, escaped_report};
use crate::peer::{Kind, Machine};
use crate::serve::CONTROL_SERVICES_SERVICE;
use crate::transport;

/// The two diagnostic services a peer serves, independent so a node may offer one without the other: `ping`
/// (cheap RTT) and `speed` (bandwidth-eating throughput). `ping`/`status` reach [`PING_SERVICE`];
/// `speed` reaches [`SPEED_SERVICE`]. Each verb dials only the service it needs, so a peer that serves only
/// one answers that verb and refuses the other. These are the names `swoosh serve` publishes by default.
pub const PING_SERVICE: &str = "ping";
/// The speed service; see [`PING_SERVICE`].
pub const SPEED_SERVICE: &str = "speed";

/// How long to wait for a machine to connect before calling it unreachable. Ten seconds is generous for a
/// real handshake (including iroh hole-punching) yet short enough that a dead machine does not feel like a
/// hang.
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);

/// How long the follow-up to a refused dial may take, its own dial included: under [`DIAL_TIMEOUT`], since
/// it runs where the person expects the verb to have ended, and a machine that admits it and never answers
/// must not hold the run open.
pub const FOLLOW_UP_TIMEOUT: Duration = Duration::from_secs(5);

/// Connect to `machine`, typed as `target`, under the [`DIAL_TIMEOUT`]. `bound` is what this run bound, so
/// a failure can point at the fix its bind needs.
pub async fn dial<T: Transport, D: Discovery>(
    node: &Node<T, D>,
    machine: &Machine,
    target: &impl core::fmt::Display,
    bound: &transport::Bound,
) -> eyre::Result<T::Session> {
    connect(node, machine.key())
        .await
        .map_err(|error| hint(unreached(target, error), bound))
}

/// Connect to `machine` for its gated `service`: the session and the connector every stream on it opens
/// through, presenting `present` (the caller's membership badge or a link) and, for a signet-bound slip,
/// `membership` in slot 2. The service handshake rides each stream later (the gate is per stream), so this
/// bounds only reaching the machine, as [`dial`] does. The session is returned raw, so a second service
/// can ride it beside the first.
pub async fn dial_service<T: Transport, D: Discovery>(
    node: &Node<T, D>,
    machine: &Machine,
    target: &impl core::fmt::Display,
    service: &Service,
    present: Option<Link>,
    membership: Option<Link>,
    bound: &transport::Bound,
) -> eyre::Result<(T::Session, Connector)> {
    let session = dial(node, machine, target, bound).await?;
    let connector = gated(machine.key(), Service::clone(service), present, membership);
    Ok((session, connector))
}

/// The error for a machine the dial did not reach: the connect's cause chain under `could not reach
/// <target>`. The chain can carry the peer's text (the reason it gave for closing), so it prints through
/// the escaper; the target is this machine's own word for the peer and prints as it is.
fn unreached(target: &impl core::fmt::Display, error: eyre::Report) -> eyre::Report {
    eyre::eyre!("could not reach {target}: {}", escaped_report(error))
}

/// Connect to `key` under the [`DIAL_TIMEOUT`], mapping a timeout to a plain unreachable error.
async fn connect<T: Transport, D: Discovery>(
    node: &Node<T, D>,
    key: NodeId,
) -> eyre::Result<T::Session> {
    match tokio::time::timeout(DIAL_TIMEOUT, node.connect(key)).await {
        Ok(Ok(session)) => Ok(session),
        Ok(Err(error)) => {
            tracing::debug!(peer = %key, %error, "machine unreachable");
            Err(eyre::Report::new(error))
        }
        Err(_elapsed) => {
            tracing::debug!(peer = %key, timeout = ?DIAL_TIMEOUT, "machine did not answer in time");
            Err(eyre::eyre!(
                "timed out after {DIAL_TIMEOUT:?} with no response"
            ))
        }
    }
}

/// The connector for `service` on `key` presenting `present` in slot 1 and, when given, `membership` in
/// slot 2: a badge under the foreign fleet a signet-bound slip in slot 1 names. Slot 2 is a no-op for a
/// plain dial, where the host admits on slot 1 alone.
pub fn gated(
    key: NodeId,
    service: Service,
    present: Option<Link>,
    membership: Option<Link>,
) -> Connector {
    let connector = Connector::to_node(key, service, present);
    match membership {
        Some(badge) => connector.with_membership(badge),
        None => connector,
    }
}

/// What a refused dial to one of your own devices learned from that device's `control.services`, which
/// only your devices reach. The list is the one the device started with, so it is the truth about what
/// it serves now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Diagnosis {
    /// The device answered, and its list does not hold the service: it does not serve it.
    NotListed,
    /// The device answered, and its list holds the service: it was turned off or removed there, or the
    /// device was too busy to take it.
    Listed,
    /// The device refused the call itself: it does not count this machine as one of your devices.
    NotYours,
    /// The call timed out, failed, or was refused some other way: no cause can be claimed.
    Unknown,
}

/// Why `machine` refused a dial of `service`, asked on `session`: one `control.services` call presenting
/// the refused dial's own `present` and `membership` slots, since the route is member-only and a call
/// presenting nothing would always be refused. Asked of your own devices only (`None` for any other
/// kind, a link included, since the refusal could then be the link's), and only after a `NotAdmitted`,
/// which the caller checks. Bounded by [`FOLLOW_UP_TIMEOUT`]; past it, or on any failure, the answer is
/// [`Diagnosis::Unknown`], which claims no cause.
///
/// Generic over the session, so a verb that holds the refused dial's session asks on it, and one that
/// holds only a gated view asks on a second connection to the same machine ([`diagnose_over`]).
pub async fn diagnose<S: Session>(
    session: &S,
    machine: &Machine,
    service: &Service,
    present: Option<Link>,
    membership: Option<Link>,
) -> Option<Diagnosis> {
    if machine.kind() != Kind::Yours {
        return None;
    }
    Some(
        tokio::time::timeout(
            FOLLOW_UP_TIMEOUT,
            ask(session, machine.key(), service, present, membership),
        )
        .await
        .unwrap_or(Diagnosis::Unknown),
    )
}

/// [`diagnose`] over a second connection to `machine` on the same `node`, for a verb whose gated view of
/// the refused session opens no other service. The same endpoint dials it, so the home key gets no second
/// registration; the dial counts against [`FOLLOW_UP_TIMEOUT`].
pub async fn diagnose_over<T: Transport, D: Discovery>(
    node: &Node<T, D>,
    machine: &Machine,
    service: &Service,
    present: Option<Link>,
    membership: Option<Link>,
) -> Option<Diagnosis> {
    if machine.kind() != Kind::Yours {
        return None;
    }
    let asked = async {
        match node.connect(machine.key()).await {
            Ok(session) => ask(&session, machine.key(), service, present, membership).await,
            Err(error) => {
                tracing::debug!(%error, "the follow-up could not reach the machine");
                Diagnosis::Unknown
            }
        }
    };
    Some(
        tokio::time::timeout(FOLLOW_UP_TIMEOUT, asked)
            .await
            .unwrap_or(Diagnosis::Unknown),
    )
}

/// The one `control.services` call: open the route with the refused dial's credentials, read the list,
/// and say whether it holds `service`. Nothing from the reply is printed, only whether the name is in it.
async fn ask<S: Session>(
    session: &S,
    key: NodeId,
    service: &Service,
    present: Option<Link>,
    membership: Option<Link>,
) -> Diagnosis {
    let Ok(route) = CONTROL_SERVICES_SERVICE.parse::<Service>() else {
        return Diagnosis::Unknown;
    };
    let (writer, reader) = match gated(key, route, present, membership)
        .open_on(session)
        .await
    {
        Ok(halves) => halves,
        Err(bifrost::Error::Refused(bifrost::Refusal::NotAdmitted)) => return Diagnosis::NotYours,
        Err(error) => {
            tracing::debug!(%error, "the follow-up call failed");
            return Diagnosis::Unknown;
        }
    };
    // The read sends nothing; dropping the write half lets the node's reply complete.
    drop(writer);
    match read_catalog(reader).await {
        Ok(catalog)
            if catalog
                .entries()
                .any(|entry| entry.name == service.as_str()) =>
        {
            Diagnosis::Listed
        }
        Ok(_) => Diagnosis::NotListed,
        Err(error) => {
            tracing::debug!(%error, "the follow-up's list did not read");
            Diagnosis::Unknown
        }
    }
}

/// Read a machine's list of services under the wire's own bound, then decode it.
///
/// The untrusted end here is the SERVER: these bytes are a remote node's, and an unbounded read lets that
/// node grow this client's buffer for as long as it cares to stream. So the bound goes on the READ, before
/// the first byte lands, and it is the wire's own [`MAX_CATALOG_BLOB`](tunnel::MAX_CATALOG_BLOB): the
/// serving end refuses to encode past the same bound, so one number holds both ends of this wire. One byte
/// past it is read only to tell a list at the ceiling (it decodes) from a peer still streaming (it does
/// not), so an over-long reply says so instead of reading as a malformed list.
pub async fn read_catalog(
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

/// Put the fact the bound transport and bind mode explain under a reach failure, and the fix under that,
/// so the error says what happened first and what to do next.
///
/// Shared by [`dial`] and the probe verbs so a `could not reach` over quirk always carries the same
/// remedy. A cause the person may have set names both its spellings, since they may only ever have set
/// the variable, and so does a remedy that removes one; a remedy that adds a flag names the flag alone,
/// since a flag beats its variable.
pub fn hint(error: eyre::Report, bound: &transport::Bound) -> eyre::Report {
    let detail = match (bound.transport, bound.local) {
        // `--local` removes internet discovery and relays, so "add --transport iroh" would be false
        // advice (iroh under it is still local). Name the setting as the cause, the hand-fed address that
        // remains, and the way back to the default bind.
        (_, true) => "With --local or SWOOSH_LOCAL, swoosh looks on this network only.\n  Give its address \
                      with --peer <key>=<address>, or drop --local and unset SWOOSH_LOCAL."
            .to_owned(),
        // quirk is direct-only with no discovery, so an unreachable machine is almost always a missing or
        // wrong address. Name the flag that gives one and the one-flag escape to a self-discovering
        // transport. The sealed spelling reaches the same way, so it carries the same remedy.
        (transport::Transport::Quirk | transport::Transport::QuirkNoise, false) => {
            "quirk finds no machine by itself.\n  Give its address with --peer <key>=<address>, or add \
             --transport iroh."
                .to_owned()
        }
        // An iroh dial over n0's resolver needs no extra line: n0 is the default everyone reads about.
        // A dial through the operator's own does, because iroh's error does not name it, so a resolver
        // that is down or empty reads as "the machine is offline" with nothing to check. Only the
        // RESOLVER is named: this node's own relay is not on the path to the machine, since a dial runs
        // through whatever relay the machine's record names, so naming it would point at the wrong server.
        (transport::Transport::Iroh, false) => match &bound.reach.resolver {
            transport::Resolver::N0 => return error,
            transport::Resolver::Custom(url) => format!("resolver asked: {url}"),
        },
    };
    // One message rather than a wrapped chain: a wrap prints first, and the fact leads.
    eyre::eyre!("{error:#}\n  {detail}")
}

/// How far a probe of one machine got, ordered by exactly that: no answer, an answer that refused, an
/// answer whose probe then broke, a full round trip. [`into_result`](Self::into_result) turns it into the
/// exit code.
///
/// An enum rather than a pile of booleans because only [`Healthy`](Self::Healthy) may exit green: a new
/// state has to name its rank here, in one exhaustive place, instead of quietly failing to set a flag and
/// inheriting success.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum Outcome {
    /// The machine did not answer the dial. The default, so a probe that reports nothing at all reads as
    /// unreachable rather than as a success.
    #[default]
    Unreachable,
    /// The machine answered the dial and refused the probe: reached, but it does not serve this.
    Refused,
    /// The machine answered the dial and was admitted, and the probe then failed mid-protocol. Ranked
    /// above a refusal because the exchange got further, not because it is better news.
    Failed,
    /// The machine answered the probe. The ONLY outcome that keeps the exit code green.
    Healthy,
}

impl Outcome {
    /// The exit of a probe verb (`ping`, `status <machine>`) from how far it got.
    ///
    /// Non-zero unless the machine answered the probe, and the failing shapes carry DIFFERENT errors so a
    /// failure that was REACHED is never dressed as an addressing problem: an unreachable machine carries
    /// the transport's reach [`hint`] (over quirk, the `--peer` remedy; under `--local`, the setting named
    /// as the cause), while a refusal or a broken probe says which it was and carries none, so a refused
    /// stranger over quirk never sees the `--peer` remedy after it already reached the node.
    pub fn into_result(
        self,
        target: &impl core::fmt::Display,
        bound: &transport::Bound,
    ) -> eyre::Result<()> {
        match self {
            Self::Healthy => Ok(()),
            Self::Failed => Err(eyre::eyre!("{target}: reached, but the probe failed")),
            Self::Refused => Err(eyre::eyre!("{target}: reached, but refused")),
            Self::Unreachable => Err(hint(eyre::eyre!("could not reach {target}"), bound)),
        }
    }
}

/// The `path:` a session takes, for the line `ping`, `speed` and `status <machine>` print: the one path
/// carrying its bytes, as the transport has selected it, read after a probe so a hole-punch that landed
/// during it reports `direct`. A direct path with a relay kept open as a standby is `direct`: the relay
/// carries nothing. A transport that does not expose its path says `unknown` rather than a reassuring
/// answer.
pub fn conn_path(info: &ConnInfo) -> PathLine<'_> {
    PathLine(&info.path)
}

/// A [`Path`] in the words a line prints it in: `direct`, `relayed through <host>`, or `unknown`.
///
/// The relay's host is the transport's report, and a relay can be named by the peer, so it prints through
/// the shared escaper, never raw. One trailing dot is dropped: iroh names its default relays fully
/// qualified (`euc1-1.relay.n0.iroh.link.`), and that root dot is the same name but reads as a sentence's
/// period at a line's end and as `link., rtt` mid-line. A relay URL with no host (not one a relay serves
/// from) prints as `relayed`, naming nothing rather than the whole URL.
#[derive(Debug, Clone, Copy)]
pub struct PathLine<'a>(pub &'a Path);

impl core::fmt::Display for PathLine<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.0 {
            Path::Direct => f.write_str("direct"),
            Path::Relayed(relay) => match relay.url().host_str() {
                Some(host) => write!(
                    f,
                    "relayed through {}",
                    Escaped(host.strip_suffix('.').unwrap_or(host))
                ),
                None => f.write_str("relayed"),
            },
            Path::Unknown => f.write_str("unknown"),
        }
    }
}

#[cfg(test)]
#[path = "reach_tests.rs"]
mod tests;
