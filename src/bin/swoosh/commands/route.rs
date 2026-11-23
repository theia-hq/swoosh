//! The path a dialing verb's streams take, its own bind or a running `swoosh serve`, for the lines an
//! outcome prints there: a verb's body is one on both paths, and each path words the same outcome its
//! own way only where the table of lines says so.

use bifrost::{NodeId, Refusal};
use swoosh::escape::{Escaped, causes, escaped_report};
use swoosh::node_client::UidSocket;
use swoosh::peer::{Machine, Peer};
use swoosh::peers::OpenError;
use swoosh::reach;
use swoosh::serve::control_codec::{OpenRefusal, PeerRefusal};
use swoosh::streams::{Ask, StreamSource, Unopened};
use swoosh::transport::Bound;

use crate::commands::connect::ConnectionLost;
use crate::commands::machine;
use crate::commands::through_serve::{Busy, Dial, Skew, StandingEnded, ThisMachine};

/// The path a run's streams take, for the lines an outcome prints: each path prints its own for the
/// same outcome.
pub enum Route<'a> {
    /// By own bind: the machine as typed and what the run bound, for an unreachable one's line, and the
    /// key it bound, for an ended standing's remedy.
    Own {
        peer: &'a Peer,
        bound: &'a Bound,
        this: NodeId,
    },
    /// Through `serve`: the dial's lines, and its socket to ask whether `serve` went.
    Serve {
        dial: &'a Dial<'a>,
        socket: &'a UidSocket,
    },
}

impl Route<'_> {
    /// The line `unopened` prints for `machine`: by own bind, the cause chain as a transport's failure
    /// prints it; through `serve`, the routed verbs' line for it.
    pub async fn line(&self, unopened: Unopened, machine: &Machine) -> eyre::Report {
        let (peer, bound, this) = match self {
            Self::Serve { dial, socket } => {
                let unattached = dial.unopened(unopened, socket).await;
                return dial.unattached(unattached, *socket).await;
            }
            Self::Own { peer, bound, this } => (*peer, *bound, *this),
        };
        match unopened {
            Unopened::Refused(OpenRefusal::Peer(refusal)) => {
                peer_error(&bifrost::Error::Refused(Refusal::from(refusal)))
            }
            Unopened::Refused(OpenRefusal::StandingEnded) => StandingEnded(Some(this)).into(),
            Unopened::Refused(OpenRefusal::NotHere) => ThisMachine::of(machine).into(),
            Unopened::Refused(OpenRefusal::Busy) => Busy.into(),
            Unopened::Refused(OpenRefusal::Unreachable(detail)) => {
                peer_error(&bifrost::Error::Connect(detail.to_string().into()))
            }
            Unopened::Refused(OpenRefusal::Timeout) => {
                peer_error(&bifrost::Error::Connect("timed out".into()))
            }
            Unopened::Refused(
                OpenRefusal::Broken(detail) | OpenRefusal::PeerUnreadable(detail),
            ) => peer_error(&bifrost::Error::Stream(detail.to_string().into())),
            Unopened::Own(error @ OpenError::Unreachable(_)) => {
                reach::open_failed(peer, error, bound)
            }
            Unopened::Own(error) => peer_error(&error),
            Unopened::Home(report) => peer_error(report.as_ref()),
            // The resident's own outcomes, which a run that bound its own never meets.
            Unopened::ServeError(reason) => escaped_report(eyre::eyre!(reason)),
            Unopened::Skew => Skew.into(),
            Unopened::Malformed(malformed) => malformed.into(),
            Unopened::ServeGone | Unopened::Control(_) => ConnectionLost.into(),
        }
    }

    /// The line a run ends with for `unopened`, which every later stream of `ask` would repeat. A
    /// machine's `NotAdmitted` is the dial refusal, after one of your devices is asked why through
    /// `source`, the path the refused stream took; anything else is [`line`](Self::line).
    pub async fn ending(
        &self,
        unopened: Unopened,
        source: &impl StreamSource,
        ask: &Ask,
        machine: &Machine,
    ) -> eyre::Report {
        match unopened {
            Unopened::Refused(OpenRefusal::Peer(PeerRefusal::NotAdmitted)) => {
                let diagnosis = reach::diagnose_through(
                    source,
                    machine,
                    &ask.service,
                    Option::clone(&ask.slip),
                )
                .await;
                machine::refused(machine, &ask.service, diagnosis)
            }
            other => self.line(other, machine).await,
        }
    }

    /// The exit of a probe of `peer` that got as far as `outcome`: by own bind an unreachable machine
    /// carries the bind's reach hint; through `serve` no bind of this run's can be the cause.
    pub fn result(&self, outcome: reach::Outcome, peer: &Peer) -> eyre::Result<()> {
        match self {
            Self::Own { bound, .. } => outcome.into_result(peer, bound),
            Self::Serve { .. } => outcome.unbound_result(peer),
        }
    }

    /// `serve`'s own line when it went, asked after a run broke; by own bind there is none to ask.
    pub async fn stopped(&self) -> Option<eyre::Report> {
        match self {
            Self::Own { .. } => None,
            Self::Serve { dial, socket } => dial.stopped(socket).await,
        }
    }

    /// `own`, the line a broken run prints, unless `serve` went under it: then `serve`'s.
    pub async fn cut_or(&self, own: eyre::Report) -> eyre::Report {
        match self {
            Self::Own { .. } => own,
            Self::Serve { dial, socket } => dial.cut_or(socket, own).await,
        }
    }
}

/// A failed stream or transfer as a line prints it: the cause chain, `outer: inner`, through the shared
/// escaper. The chain can carry the peer's text (a refusal detail, the reason it gave for closing), so it
/// is escaped here, where it enters, and not on a skip line, which would escape a path it names twice.
pub fn peer_error(error: &dyn core::error::Error) -> eyre::Report {
    eyre::eyre!("{}", Escaped(&causes(error)))
}
