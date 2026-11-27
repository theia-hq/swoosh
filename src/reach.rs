//! Reach a resolved [`Machine`]: the lines a dial that reached nothing prints, and the one follow-up a
//! refused dial to one of your own devices makes to learn why.
//!
//! A verb resolves its peer to exactly one machine before anything binds ([`Peer::machine`]), so every
//! reach here is to one key. Its streams come from a [`StreamSource`], whose dials are bounded there,
//! so a wedged machine reads as unreachable rather than as a hang.
//!
//! [`Peer::machine`]: crate::peer::Peer::machine

use core::time::Duration;

use bifrost::{ConnInfo, NodeId, Path};
use nauthy::{Link, Service};
use tightbeam::tunnel::{self, Connector};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

use crate::escape::{Escaped, beside, causes, escaped_report};
use crate::peer::{Kind, Machine};
use crate::peers::{Hints, OpenError};
use crate::serve::CONTROL_SERVE_SERVICE;
use crate::serve::control::{Answer, Request};
use crate::serve::control_codec::{OpenLane, OpenRefusal, PeerRefusal};
use crate::streams::{Ask, StreamSource, Unopened};
use crate::transport;

/// The two diagnostic services a peer serves, independent so a node may offer one without the other: `ping`
/// (cheap RTT) and `speed` (bandwidth-eating throughput). `ping`/`status` reach [`PING_SERVICE`];
/// `speed` reaches [`SPEED_SERVICE`]. Each verb dials only the service it needs, so a peer that serves only
/// one answers that verb and refuses the other. These are the names `swoosh serve` publishes by default.
pub const PING_SERVICE: &str = "ping";
/// The speed service; see [`PING_SERVICE`].
pub const SPEED_SERVICE: &str = "speed";

/// How long the follow-up to a refused dial may take, its own dial included: under a dial's own ten
/// seconds, since it runs where the person expects the verb to have ended, and a machine that admits it and never answers
/// must not hold the run open.
pub const FOLLOW_UP_TIMEOUT: Duration = Duration::from_secs(5);

/// The error for an open through the run's [`Peers`](crate::peers::Peers) that gave no stream: a dial that
/// reached no session reads `could not reach <machine>`, with the fix `bound` needs; any other failure keeps
/// its chain, escaped, since it can carry the peer's text.
pub fn open_failed(machine: &Machine, error: OpenError, bound: &transport::Bound) -> eyre::Report {
    match error {
        OpenError::Unreachable(failure) => hint(
            machine,
            unreached(machine, eyre::Report::new(failure)),
            bound,
        ),
        other => escaped_report(other.into()),
    }
}

/// The error for a machine the dial did not reach: the connect's cause chain under `could not reach
/// <machine>`. The chain can carry the peer's text (the reason it gave for closing), so it prints as a peer
/// cell, escaped and cut to the room the `error:` line leaves; the label is this machine's own word for the
/// peer and prints as it is.
fn unreached(machine: &Machine, error: eyre::Report) -> eyre::Report {
    let words = format!("could not reach {}: ", machine.label());
    eyre::eyre!(
        "{}",
        beside("error: ".len(), &words, &format!("{error:#}"), "")
    )
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

/// What a refused dial to one of your own devices learned from that device's list on `control.serve`,
/// which only your devices reach. The list is the one the device started with, so it is the truth about what
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

/// Why `machine` refused a stream of `service`, asked through `source`, the path the refused stream
/// took: one `control.serve` stream on Main asking for its list, presenting `slip` when the machine was
/// typed as a link, else what `source` presents for the route, since the route is member-only and a call
/// presenting nothing would always be refused. Asked of your own devices only (`None` for any other kind, a link
/// included, since the refusal could then be the link's), and only after a `NotAdmitted`, which the
/// caller checks. Bounded by [`FOLLOW_UP_TIMEOUT`]; past it, or on any failure, the answer is
/// [`Diagnosis::Unknown`], which claims no cause.
pub async fn diagnose_through(
    source: &impl StreamSource,
    machine: &Machine,
    service: &Service,
    slip: Option<Link>,
) -> Option<Diagnosis> {
    if machine.kind() != Kind::Yours {
        return None;
    }
    let asked = async {
        let Ok(route) = CONTROL_SERVE_SERVICE.parse::<Service>() else {
            return Diagnosis::Unknown;
        };
        let ask = Ask {
            peer: machine.key(),
            hints: Hints::NONE,
            service: route,
            lane: OpenLane::Main,
            slip,
        };
        match source.open(&ask).await {
            Ok(opened) => listed(opened.write, opened.read, service).await,
            Err(Unopened::Refused(OpenRefusal::Peer(PeerRefusal::NotAdmitted))) => {
                Diagnosis::NotYours
            }
            Err(unopened) => {
                tracing::debug!(?unopened, "the follow-up call failed");
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

/// Whether the list the stream's machine answers holds `service`. Nothing from it is printed.
async fn listed(
    writer: impl AsyncWrite + Unpin,
    reader: impl AsyncRead + Unpin,
    service: &Service,
) -> Diagnosis {
    match ask_list(writer, reader).await {
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

/// How a list request failed in a way swoosh tells in its own words, apart from a transport's cause chain,
/// which can carry the peer's text: a caller that prints it knows it holds no text of the machine's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ListFailed {
    /// The machine answered the list request with anything but [`Answer::Done`], or sent a list that does
    /// not decode. Whatever it sent stays in the log, since it is the machine's own bytes.
    #[error("it sent an unknown reply to the list request")]
    UnknownReply,
    /// The machine ended its side cleanly before it answered. It sent nothing, so nothing it sent was
    /// unknown.
    #[error("it ended the list request without an answer")]
    Ended,
    /// The machine sent more than a list can be, past the wire's own bound.
    #[error(
        "it sent more than a list of services can be, so the read stopped at {} bytes",
        tunnel::MAX_CATALOG_BLOB
    )]
    TooLong,
}

/// Ask the machine on an opened `control.serve` stream for its list of services: write
/// [`Request::List`] and end this side, then read the one answer byte and, after [`Answer::Done`], the
/// list. The caller bounds the whole exchange.
///
/// This side is ended, not dropped, since through `serve` a half dropped unended reaches the node as a
/// reset. A transport failure keeps its cause; a clean end before any answer is [`ListFailed::Ended`]; an
/// answer that is not `Done` and a list that does not decode are both [`ListFailed::UnknownReply`]. A node answers a list `Done` whether or not
/// its first round has ended, so any other answer is one no conforming node gives.
pub async fn ask_list(
    mut writer: impl AsyncWrite + Unpin,
    mut reader: impl AsyncRead + Unpin,
) -> eyre::Result<tunnel::ServiceCatalog> {
    let failed = |error: tokio::io::Error| eyre::eyre!("{}", causes(&error));
    writer
        .write_all(&[Request::List.encode()])
        .await
        .map_err(failed)?;
    writer.shutdown().await.map_err(failed)?;
    let mut answer = [0u8; 1];
    match reader.read_exact(&mut answer).await {
        Ok(_) => {}
        // A conforming node resets a stream it does not answer, so a clean end is no answer at all.
        Err(error) if error.kind() == tokio::io::ErrorKind::UnexpectedEof => {
            tracing::debug!("the list request's stream ended before an answer");
            return Err(ListFailed::Ended.into());
        }
        Err(error) => return Err(failed(error)),
    }
    if Answer::decode(answer[0]) != Some(Answer::Done) {
        tracing::debug!(
            answer = answer[0],
            "the list request was answered with another code"
        );
        return Err(ListFailed::UnknownReply.into());
    }
    read_catalog(reader).await
}

/// Read a machine's list of services under the wire's own bound, then decode it.
///
/// The untrusted end here is the SERVER: these bytes are a remote node's, and an unbounded read lets that
/// node grow this client's buffer for as long as it cares to stream. So the bound goes on the READ, before
/// the first byte lands, and it is the wire's own [`MAX_CATALOG_BLOB`](tunnel::MAX_CATALOG_BLOB): the
/// serving end refuses to encode past the same bound, so one number holds both ends of this wire. One byte
/// past it is read only to tell a list at the ceiling (it decodes) from a peer still streaming (it does
/// not), so an over-long reply says so instead of reading as a malformed list.
async fn read_catalog(reader: impl AsyncRead + Unpin) -> eyre::Result<tunnel::ServiceCatalog> {
    let mut bytes = Vec::new();
    reader
        .take(tunnel::MAX_CATALOG_BLOB + 1)
        .read_to_end(&mut bytes)
        .await
        .map_err(|error| eyre::eyre!("{}", causes(&error)))?;
    if bytes.len() as u64 > tunnel::MAX_CATALOG_BLOB {
        return Err(ListFailed::TooLong.into());
    }
    tunnel::ServiceCatalog::decode(&bytes).map_err(|error| {
        tracing::debug!(%error, "the list did not decode");
        ListFailed::UnknownReply.into()
    })
}

/// Put the fact the bind mode explains under a reach failure, and the fix under that, so the error says
/// what happened first and what to do next.
///
/// Shared by every dial's line so a `could not reach` always carries the same remedy. A cause the person
/// may have set names both its spellings, since they may only ever have set the variable; a remedy that
/// adds a flag names the flag alone, since a flag beats its variable.
pub fn hint(machine: &Machine, unreached: eyre::Report, bound: &transport::Bound) -> eyre::Report {
    if bound.local {
        // The cause chain says how the dial failed, which the person cannot act on: the remedy is the
        // address only the machine itself can list. The chain stays in the log, escaped already.
        tracing::debug!(error = %format_args!("{unreached:#}"), "a --local dial reached nothing");
        return local_miss(machine);
    }
    // A dial over n0's resolver needs no extra line: n0 is the default everyone reads about. A dial through
    // the operator's own does, because iroh's error does not name it, so a resolver that is down or empty
    // reads as "the machine is offline" with nothing to check. Only the RESOLVER is named: this node's own
    // relay is not on the path to the machine, since a dial runs through whatever relay the machine's
    // record names, so naming it would point at the wrong server.
    match &bound.reach.resolver {
        transport::Resolver::N0 => unreached,
        // One message rather than a wrapped chain: a wrap prints first, and the fact leads.
        transport::Resolver::Custom(url) => {
            eyre::eyre!("{unreached:#}\n  resolver asked: {url}")
        }
    }
}

/// The refusal for a `--local` dial that reached nothing: `--local` drops internet discovery and relays,
/// so only an address on this network or one given by hand can reach the machine. It names the machine,
/// where its addresses are listed (on the machine itself, which only a name here can point at), and the
/// `--peer` form with the whole key, so the line can be completed by pasting one address.
fn local_miss(machine: &Machine) -> eyre::Report {
    let on = machine
        .name()
        .map_or_else(|| "that machine".to_owned(), ToString::to_string);
    // The second sentence wraps at its comma: whole, it runs past the screen's 80 columns.
    eyre::eyre!(
        "could not reach {label} on this network\n  \
         With --local or SWOOSH_LOCAL, swoosh looks for it on this network,\n  \
         or at an address you give.\n  \
         On {on}, swoosh status lists its addresses under reach.\n  \
         Add one of those addresses to your command:\n    \
         --peer {key}=<address>",
        label = machine.label(),
        key = machine.key(),
    )
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
    /// the bind's reach [`hint`] (under `--local`, where the machine lists its addresses and the `--peer`
    /// form), while a refusal or a broken probe says which it was and carries none, so a refused stranger
    /// never sees the `--peer` remedy after it already reached the node.
    pub fn into_result(self, machine: &Machine, bound: &transport::Bound) -> eyre::Result<()> {
        match self {
            Self::Unreachable => Err(hint(
                machine,
                eyre::eyre!("could not reach {}", machine.label()),
                bound,
            )),
            reached => reached.unbound_result(&machine.label()),
        }
    }

    /// [`into_result`](Self::into_result) for a run that made no bind of its own, such as one through a
    /// local resident: no bind's reach setting can be the cause of an unreachable machine, so none is
    /// named.
    pub fn unbound_result(self, target: &impl core::fmt::Display) -> eyre::Result<()> {
        match self {
            Self::Healthy => Ok(()),
            Self::Failed => Err(eyre::eyre!("{target}: reached, but the probe failed")),
            Self::Refused => Err(eyre::eyre!("{target}: reached, but refused")),
            Self::Unreachable => Err(eyre::eyre!("could not reach {target}")),
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
