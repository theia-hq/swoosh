//! `forward <machine> <service> -` through a running `swoosh serve`: the first verb that dials through
//! the resident rather than binding this home's key.
//!
//! When `serve` answers on this home's control socket, the pipe is one Open there: this process binds
//! nothing, reads no key and asks no passphrase, and the resident presents this home's standing (or the
//! link typed as the machine). When no `serve` runs, the verb binds its own as before. Once `serve` has
//! answered, a failure is reported, never retried by an own bind.
//!
//! The lines a resident's outcome prints are the own bind's, so one line has one shape on both paths;
//! only a busy `serve`, a `serve` that stopped under the pipe, a different `serve` version and a reach
//! flag `serve` makes moot have lines of their own.

use bifrost::Refusal;
use nauthy::{Link, Service};
use swoosh::contacts::Contacts;
use swoosh::escape::escaped_report;
use swoosh::node_client::{Opened, UidSocket};
use swoosh::peer::{Kind, Machine as PeerMachine};
use swoosh::peers::Hints;
use swoosh::serve::control_codec::{ControlError, OpenLane, OpenRefusal, OpenRequest, PeerRefusal};
use swoosh::transport::ReachArgs;
use tokio::io;

use crate::commands::connect::{ConnectionLost, Machine, pump_stdio, stdin_chunks};
use crate::commands::machine;

/// Whether a run took the resident's path.
pub enum Routed {
    /// No `serve` answers here: the verb binds its own.
    OwnBind,
    /// The pipe ran through `serve`, to this end.
    Ran(eyre::Result<()>),
}

/// A `forward <machine> <service> -` to dial, as the resident needs it.
pub struct Pipe<'a> {
    /// The machine the verb dials.
    pub machine: &'a PeerMachine,
    /// The service it asks for.
    pub service: &'a Service,
    /// The link typed as the machine, if one was: the resident presents it as the slip.
    pub slip: Option<Link>,
    /// The verb's reach flags: `--peer` hints ride the Open; the rest cannot apply to a bind it does not
    /// make.
    pub reach: &'a ReachArgs,
    /// This home's book, to name the machine.
    pub contacts: &'a Contacts,
}

/// Run `pipe` through the `serve` at `home`'s control socket when one answers.
///
/// # Errors
///
/// The control socket cannot be trusted; never an own bind then.
pub async fn forward(home: &swoosh::home::Home, pipe: Pipe<'_>) -> eyre::Result<Routed> {
    let socket = match UidSocket::resolve(home) {
        Ok(socket) => socket,
        Err(ControlError::NoResident) => return Ok(Routed::OwnBind),
        Err(error) => return Err(error.into()),
    };
    let connected = match socket.connected().await {
        Ok(connected) => connected,
        Err(ControlError::NoResident) => return Ok(Routed::OwnBind),
        Err(error) => return Err(error.into()),
    };
    Ok(Routed::Ran(pipe.run(&socket, connected).await))
}

impl Pipe<'_> {
    async fn run(
        mut self,
        socket: &UidSocket,
        connected: swoosh::node_client::Connected,
    ) -> eyre::Result<()> {
        if let Some(moot) = Moot::first(self.reach) {
            return Err(moot.into());
        }
        let key = self.machine.key();
        let hints = Hints::new(
            self.reach
                .peer
                .iter()
                .filter(|hint| hint.node() == key)
                .flat_map(|hint| hint.addrs().iter().copied()),
        )?;
        // Main: an ordinary pipe. Bulk is a fan-out's lane, Isolated a measurement's.
        let request = OpenRequest::new(
            key,
            hints,
            self.service.clone(),
            OpenLane::Main,
            self.slip.take(),
        )?;
        let (read, write) = match connected.open(request).await {
            Ok(Opened::Attached { read, write, .. }) => (read, write),
            Ok(Opened::Refused(refusal)) => return Err(self.refused(refusal)),
            Ok(Opened::Error(reason)) => return Err(escaped_report(eyre::eyre!(reason))),
            Err(ControlError::Version { .. }) => return Err(Skew.into()),
            Err(error) => {
                tracing::debug!(%error, "an open through serve failed before its reply");
                return Err(self.cut(socket).await);
            }
        };
        match pump_stdio(write, read, stdin_chunks()?, io::stdout()).await {
            Err(report) if report.is::<ConnectionLost>() => Err(self.cut(socket).await),
            ended => ended,
        }
    }

    /// The line a refusal prints: the own bind's for the same outcome, except `Busy` and `NotHere`.
    fn refused(&self, refusal: OpenRefusal) -> eyre::Report {
        match refusal {
            // No session to ask one of your devices why, so the line names no cause it cannot tell.
            OpenRefusal::Peer(PeerRefusal::NotAdmitted) => {
                machine::refused(self.machine, self.service, None)
            }
            OpenRefusal::Peer(refusal) => {
                escaped_report(bifrost::Error::Refused(Refusal::from(refusal)).into())
            }
            OpenRefusal::Unreachable(detail) => {
                escaped_report(bifrost::Error::Connect(detail.to_string().into()).into())
            }
            OpenRefusal::Timeout => {
                escaped_report(bifrost::Error::Connect("timed out".into()).into())
            }
            OpenRefusal::Broken(detail) | OpenRefusal::PeerUnreadable(detail) => {
                escaped_report(bifrost::Error::Stream(detail.to_string().into()).into())
            }
            OpenRefusal::Busy => Busy.into(),
            OpenRefusal::StandingEnded => StandingEnded.into(),
            OpenRefusal::NotHere => ThisMachine::of(self.machine).into(),
        }
    }

    /// The line a pipe cut off prints: `serve`'s own when it no longer answers, else the cut-off's.
    async fn cut(&self, socket: &UidSocket) -> eyre::Report {
        let named = Machine::of(self.contacts, self.machine.key());
        after_a_cut(socket.status_attributed().await.map(drop), &named)
    }
}

/// The line for a cut-off pipe, from what asking `serve` again gave: `serve`'s own line when nothing
/// answers there, else the cut-off's. An answer that is not a status still counts as one: something
/// listens, so the cut was not `serve` going.
fn after_a_cut(asked: Result<(), ControlError>, machine: &Machine) -> eyre::Report {
    match asked {
        Err(ControlError::NoResident | ControlError::Io(_) | ControlError::Timeout { .. }) => {
            ServeStopped(machine.to_string()).into()
        }
        _ => ConnectionLost.into(),
    }
}

/// A reach flag set while `serve` answers: it applies to a bind this run does not make.
#[derive(Debug, thiserror::Error)]
#[error(
    "{0} does not apply while swoosh serve runs here\n  Commands here connect through swoosh \
     serve.\n  Set it on swoosh serve, or stop swoosh serve and run this command again."
)]
pub struct Moot(&'static str);

impl Moot {
    /// The first reach flag set, in the order the line names them, both spellings.
    fn first(reach: &ReachArgs) -> Option<Self> {
        if reach.local {
            Some(Self("--local or SWOOSH_LOCAL"))
        } else if reach.relay.is_some() {
            Some(Self("--relay or SWOOSH_RELAY"))
        } else if reach.resolver.is_some() {
            Some(Self("--resolver or SWOOSH_RESOLVER"))
        } else {
            None
        }
    }
}

/// `serve`'s cap on the connections through it is full.
#[derive(Debug, thiserror::Error)]
#[error(
    "too many connections open through swoosh serve on this machine\n  Close one, or wait for one to \
     end, then try again."
)]
pub struct Busy;

/// `serve` stopped under a live pipe, or before it answered.
#[derive(Debug, thiserror::Error)]
#[error(
    "swoosh serve stopped here and ended the connection to {0}\n  Commands here connect through it \
     while it runs.\n  Run this command again to reconnect."
)]
pub struct ServeStopped(String);

/// The `serve` answering is another version of swoosh.
#[derive(Debug, thiserror::Error)]
#[error("swoosh serve on this machine is a different version\n  Restart it with this version.")]
pub struct Skew;

/// This home's standing has ended and `serve` could not renew it.
// The own bind's dead-badge line names the badge's date and a remedy keyed to this machine; reading
// either here can load the root key, which a run through `serve` never does. So the line's own head,
// with no date. Its words are owed a ruling (CLI-Architect, Editor).
#[derive(Debug, thiserror::Error)]
#[error("this device's membership badge has ended, so a family-gated peer will refuse this dial")]
pub struct StandingEnded;

/// The machine typed is this one: a usage error, exit 2.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct ThisMachine(String);

impl ThisMachine {
    /// The line for `machine`, as it was typed: its name, a key or a link.
    fn of(machine: &PeerMachine) -> Self {
        Self(match (machine.name(), machine.kind()) {
            (Some(name), _) => format!("{name} is this machine"),
            (None, Kind::Link) => "that link is for this machine".to_owned(),
            (None, _) => "that key is this machine's".to_owned(),
        })
    }
}

#[cfg(test)]
#[path = "through_serve_tests.rs"]
mod tests;
