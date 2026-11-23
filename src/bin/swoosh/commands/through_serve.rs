//! The resident's side of a dialing verb: finding a running `swoosh serve`, and the line each outcome
//! of an Open through it prints.
//!
//! When `serve` answers on this home's control socket, each stream a verb opens is one Open there: this
//! process binds nothing, reads no key and asks no passphrase, and the resident presents this home's
//! standing (or the link typed as the machine). When no `serve` runs, the verb binds its own. Once
//! `serve` has answered, a failure is reported, never retried by an own bind.
//!
//! A verb's body is one on both paths, over the run's stream source, worded by its
//! [`Route`](crate::commands::route::Route). What is left here is what only the resident's path has:
//! [`serve`] to find it, the reach flags it makes moot ([`Moot`]) and the `--peer` hints its Opens carry
//! ([`hints`]), the lines [`Dial`] words for an Open that attached nothing, and how a run whose path it
//! observed ends ([`failed`], [`ended`]).

use std::collections::HashMap;

use bifrost::{ConnInfo, NodeId, Refusal};
use nauthy::Service;
use swoosh::contacts::Contacts;
use swoosh::escape::escaped_report;
use swoosh::node_client::{Connected, NodeClient, UidSocket};
use swoosh::observation::{Follow, Observed};
use swoosh::peer::{Kind, Machine as PeerMachine};
use swoosh::peers::{Hints, HintsError};
use swoosh::serve::control_codec::{ControlError, OpenRefusal, PeerRefusal};
use swoosh::streams::Unopened;
use swoosh::transport::ReachArgs;

use crate::commands::connect::{ConnectionLost, Machine};
use crate::commands::machine;
use crate::commands::route::peer_error;

/// A verb's dial, as the resident needs it.
pub struct Dial<'a> {
    /// The machine the verb dials.
    pub machine: &'a PeerMachine,
    /// The service it asks for.
    pub service: &'a Service,
    /// This home's book, to name the machine.
    pub contacts: &'a Contacts,
}

/// The `serve` at `home`'s control socket, with a connection to it checked and nothing sent, or `None`
/// when no `serve` answers here.
///
/// # Errors
///
/// The control socket cannot be trusted; never an own bind then.
pub async fn serve(home: &swoosh::home::Home) -> eyre::Result<Option<(UidSocket, Connected)>> {
    let socket = match UidSocket::resolve(home) {
        Ok(socket) => socket,
        Err(ControlError::NoResident) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    match socket.connected().await {
        Ok(connected) => Ok(Some((socket, connected))),
        Err(ControlError::NoResident) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// Refuse a reach flag `serve` makes moot before a verb's local act, when `serve` answers here: the
/// act would land and its exchange would refuse after it. With no reach flag set the socket is not
/// probed.
///
/// # Errors
///
/// The flag's line, or the control socket cannot be trusted.
pub async fn refuse_moot(home: &swoosh::home::Home, reach: &ReachArgs) -> eyre::Result<()> {
    let Some(moot) = Moot::first(reach) else {
        return Ok(());
    };
    match serve(home).await? {
        Some(_) => Err(moot.into()),
        None => Ok(()),
    }
}

/// The `--peer` addresses as each machine's hints, by its key, checked before anything is read or
/// written: the addresses typed for one machine go to its Opens alone.
///
/// # Errors
///
/// [`CrowdedHints`] past the addresses one Open carries for a machine, or [`UnusableHint`] for one no
/// machine can be reached at: each a usage error.
pub fn hints(reach: &ReachArgs) -> eyre::Result<HashMap<NodeId, Hints>> {
    reach.reject_crowded_hints()?;
    let mut addrs: HashMap<NodeId, Vec<core::net::SocketAddr>> = HashMap::new();
    for hint in &reach.peer {
        addrs
            .entry(hint.node())
            .or_default()
            .extend_from_slice(hint.addrs());
    }
    addrs
        .into_iter()
        .map(|(key, addrs)| match Hints::new(addrs) {
            Ok(hints) => Ok((key, hints)),
            Err(HintsError::Unusable) => Err(UnusableHint.into()),
            Err(error) => Err(error.into()),
        })
        .collect()
}

/// A `--peer` address that is never a machine's endpoint: a usage error, exit 2.
#[derive(Debug, thiserror::Error)]
#[error("--peer or SWOOSH_PEER gives an address no machine can be reached at")]
pub struct UnusableHint;

impl Dial<'_> {
    /// What an Open that attached nothing means to this dial: the resident's or the peer's refusal kept
    /// typed, else the line it prints. A control connection that failed before its reply is `serve`'s
    /// own line when `serve` is gone, else a cut. A reply that never came is [`Unresponsive`] only when
    /// `serve` then fails a status too: a slow machine behind a `serve` that answers is never read as
    /// `serve` stalled.
    pub(crate) async fn unopened(&self, unopened: Unopened, socket: &UidSocket) -> Unattached {
        match unopened {
            Unopened::Refused(refusal) => Unattached::Refused(refusal),
            Unopened::ServeError(reason) => Unattached::Failed(escaped_report(eyre::eyre!(reason))),
            Unopened::Skew => Unattached::Failed(Skew.into()),
            Unopened::ServeGone => Unattached::Failed(self.serve_stopped()),
            Unopened::Malformed(malformed) => Unattached::Failed(malformed.into()),
            Unopened::Control(error @ ControlError::Timeout { .. }) => {
                tracing::debug!(%error, "an open through serve got no reply in time");
                if socket.stalled().await {
                    Unattached::Failed(Unresponsive.into())
                } else {
                    Unattached::Failed(self.cut(socket).await)
                }
            }
            // A socket that cannot be trusted keeps its own error, never a cut's.
            Unopened::Control(error @ ControlError::Untrusted { .. }) => {
                Unattached::Failed(error.into())
            }
            Unopened::Control(error) => {
                tracing::debug!(%error, "an open through serve failed before its reply");
                Unattached::Failed(self.cut(socket).await)
            }
            // The own bind's outcomes, which an Open through `serve` never gives. Escaped all the same:
            // their chains can carry the peer's text, and the types do not tie a route to its source.
            Unopened::Own(error) => Unattached::Failed(escaped_report(error.into())),
            Unopened::Home(report) => Unattached::Failed(peer_error(report.as_ref())),
        }
    }

    /// The line an Open that attached nothing prints, when the verb prints none of its own for it.
    pub async fn unattached(
        &self,
        unattached: Unattached,
        serve: &impl NodeClient,
    ) -> eyre::Report {
        match unattached {
            Unattached::Refused(refusal) => self.refused(refusal, serve).await,
            Unattached::Failed(report) => report,
        }
    }

    /// The line the run ends with when `serve` is gone.
    pub(crate) fn serve_stopped(&self) -> eyre::Report {
        self.stopped_line().into()
    }

    /// [`serve_stopped`](Self::serve_stopped)'s line, typed, for a verb that words it further.
    pub(crate) fn stopped_line(&self) -> ServeStopped {
        ServeStopped(Machine::of(self.contacts, self.machine.key()).to_string())
    }

    /// The line a refusal prints: the own bind's for the same outcome, except `Busy` and `NotHere`.
    /// `serve` is asked its status only for an ended standing, whose remedy names this machine's key.
    pub(crate) async fn refused(
        &self,
        refusal: OpenRefusal,
        serve: &impl NodeClient,
    ) -> eyre::Report {
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
            OpenRefusal::StandingEnded => {
                let this = match serve.status().await {
                    Ok(status) => Some(status.node_id),
                    Err(error) => {
                        tracing::debug!(%error, "serve's status for the ended standing's remedy failed");
                        None
                    }
                };
                StandingEnded(this).into()
            }
            OpenRefusal::NotHere => ThisMachine::of(self.machine).into(),
        }
    }

    /// The line a stream cut off prints: `serve`'s own when it no longer answers, else the cut-off's.
    async fn cut(&self, socket: &UidSocket) -> eyre::Report {
        self.cut_or(socket, ConnectionLost.into()).await
    }

    /// `serve`'s own line when it no longer answers, else `own`, the line the own bind prints for the
    /// same end.
    pub async fn cut_or(&self, socket: &UidSocket, own: eyre::Report) -> eyre::Report {
        self.stopped(socket).await.unwrap_or(own)
    }

    /// `serve`'s own line when it is gone, asked after a run broke: `None` while anything answers, or
    /// stalls, there, and the break is the run's own, so the line never claims `serve` stopped when it
    /// did not. The ask is bounded ([`UidSocket::gone`]), so a resident that accepts and stalls cannot
    /// hold a failed run's exit.
    pub async fn stopped(&self, socket: &UidSocket) -> Option<eyre::Report> {
        let named = Machine::of(self.contacts, self.machine.key());
        socket
            .gone()
            .await
            .then(|| ServeStopped(named.to_string()).into())
    }
}

/// Raise this process's open-file limit for a listener, on both paths: through `serve` each pipe holds
/// two descriptors, its local connection and its control connection, so a full listener of
/// [`MAX_PIPES`](crate::commands::connect::MAX_PIPES) takes 192 of the 256 macOS starts a process with,
/// leaving little for the run's own. It costs nothing by own bind. A run that cannot raise it still
/// listens, with fewer pipes.
pub fn raise_open_files() {
    if let Err(error) = swoosh::serve::raise_open_files() {
        tracing::warn!(%error, "could not raise the open-file limit");
    }
}

/// Why an Open through `serve` attached no stream: the resident's typed refusal, which a probe verb
/// prints its own bind's line for, or the line for anything else.
pub enum Unattached {
    /// The resident or the peer refused the Open.
    Refused(OpenRefusal),
    /// The Open failed some other way: the line it prints.
    Failed(eyre::Report),
}

/// A run through `serve` that failed after its Open attached, its error already printed by [`failed`]:
/// the composition root exits 1 and prints nothing more.
#[derive(Debug, thiserror::Error)]
#[error("the run's error was printed before its path was read")]
pub struct Reported;

/// How long past its spacing a failed run's Finish may take before the run exits without it. The run
/// prints no path, so nothing waits on the reply; a resident that accepts the query and stalls lets the
/// reference go at the end of its retention instead.
const FAILED_FINISH_GRACE: core::time::Duration = core::time::Duration::from_secs(1);

/// End a run that failed after its stream attached: print `report` on `err` as the composition root
/// prints a run's error, then Finish `observer`, in this task, before the process exits. The error never
/// waits on a reading it does not show, and through `serve` the resident lets the reference go now
/// rather than at the end of its retention; by own bind the reading is the session's, at once. The Finish gets what is left of its spacing plus
/// [`FAILED_FINISH_GRACE`], and is dropped past that. Returns [`Reported`].
pub async fn failed(
    report: eyre::Report,
    observer: impl Follow,
    err: &mut impl std::io::Write,
) -> eyre::Report {
    crate::print_error(&report, err);
    match observer.finish_within(FAILED_FINISH_GRACE).await {
        Some(observed) => log_path(observed),
        None => tracing::debug!("the failed run's Finish passed its bound and was dropped"),
    }
    Reported.into()
}

/// End a run whose result is `ended`, its own lines already printed: a failure as
/// [`failed`] ends one, a success once its observation is Finished, so no exit leaves the reference to
/// the resident's retention.
pub async fn ended(
    ended: eyre::Result<()>,
    observer: impl Follow,
    err: &mut impl std::io::Write,
) -> eyre::Result<()> {
    match ended {
        Ok(()) => {
            log_path(observer.finish().await);
            Ok(())
        }
        Err(report) => Err(failed(report, observer, err).await),
    }
}

/// Log the observation of a run through `serve` that prints no path: its own line is what it prints.
pub fn log_path(observed: Observed) {
    if let Some(earlier) = &observed.earlier {
        tracing::debug!(%earlier, "a sample of the run's path failed");
    }
    if let Err(error) = &observed.last {
        tracing::debug!(%error, "the run's final path could not be read");
    }
}

/// The path text a run through `serve` prints, from its final observation, the Finish's: `None` when
/// that failed, and `err` then carries a warning while the run's own result and exit stay as they are.
/// A sample that failed earlier is never shown: it goes to the log, at debug.
///
/// # Errors
///
/// The warning could not be written.
pub fn final_path(
    observed: Observed,
    err: &mut impl std::io::Write,
) -> std::io::Result<Option<ConnInfo>> {
    if let Some(earlier) = &observed.earlier {
        tracing::debug!(%earlier, "a sample of the run's path failed");
    }
    match observed.last {
        Ok(info) => Ok(Some(info)),
        Err(error) => {
            tracing::debug!(%error, "the run's final path could not be read");
            writeln!(err, "warning: could not read the path of this run")?;
            Ok(None)
        }
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
    pub(crate) fn first(reach: &ReachArgs) -> Option<Self> {
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

/// `serve` is there and took no connection, or gave no reply in time.
#[derive(Debug, thiserror::Error)]
#[error("swoosh serve on this machine did not answer\n  Restart it.")]
pub struct Unresponsive;

/// `serve` stopped under a live pipe, or before it answered.
#[derive(Debug, thiserror::Error)]
#[error(
    "swoosh serve stopped here and ended the connection to {0}\n  Commands here connect through it \
     while it runs.\n  Run this command again to reconnect."
)]
pub struct ServeStopped(String);

/// `serve` stopped under a root act's exchange with `machine`, after the act landed: no rerun is
/// advised, since the act is done and the started `serve` asks your devices itself.
#[derive(Debug, thiserror::Error)]
#[error(
    "swoosh serve stopped here and ended the connection to {0}\n  Commands here connect through it \
     while it runs.\n  Start it again; it asks your devices as it starts."
)]
pub struct StoppedAfterAct(pub(crate) String);

/// `serve` stopped under a `send` after at least one file printed `sent`: a bare rerun would send those
/// again, so the line says what is left.
#[derive(Debug, thiserror::Error)]
pub enum StoppedAfterSent {
    /// Files remain unsent: the rerun leaves out the ones already sent.
    #[error(
        "swoosh serve stopped here and ended the connection to {0}\n  Commands here connect through it \
         while it runs.\n  Run this command again to reconnect, without the files already marked `sent`."
    )]
    FilesLeft(String),
    /// Every file printed `sent`: nothing is left to send, so no rerun is advised.
    #[error(
        "swoosh serve stopped here and ended the connection to {0}\n  Commands here connect through it \
         while it runs.\n  Every file was marked `sent`."
    )]
    AllSent(String),
}

impl ServeStopped {
    /// The line for the connection to `machine`, as a line names it.
    pub(crate) fn to(machine: impl core::fmt::Display) -> Self {
        Self(machine.to_string())
    }

    /// This stop, met by a `send` with files still unsent after at least one printed `sent`.
    pub(crate) fn after_sent(self) -> StoppedAfterSent {
        StoppedAfterSent::FilesLeft(self.0)
    }

    /// This stop, met by a `send` after every one of its files printed `sent`.
    pub(crate) fn after_all_sent(self) -> StoppedAfterSent {
        StoppedAfterSent::AllSent(self.0)
    }
}

/// The `serve` answering is another version of swoosh.
#[derive(Debug, thiserror::Error)]
#[error("swoosh serve on this machine is a different version\n  Restart it with this version.")]
pub struct Skew;

/// This home's standing has ended and `serve` could not renew it: the own bind's dead-badge line, with
/// the remedy keyed to this machine's key as `serve`'s status gives it, or the head alone when that
/// status cannot be read.
// The own bind's line names the badge's date too; reading it here can load the root key, which a run
// through `serve` never does, so the head says only that the badge has ended.
#[derive(Debug)]
pub struct StandingEnded(pub(crate) Option<NodeId>);

impl core::fmt::Display for StandingEnded {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(
            "this device's membership badge has ended, so a family-gated peer will refuse this dial",
        )?;
        match self.0 {
            Some(this) => write!(f, "; {}", swoosh::badge::remedy(this)),
            None => Ok(()),
        }
    }
}

impl core::error::Error for StandingEnded {}

/// The machine typed is this one: a usage error, exit 2.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct ThisMachine(String);

impl ThisMachine {
    /// The line for `machine`, as it was typed: its name, a key or a link.
    pub(crate) fn of(machine: &PeerMachine) -> Self {
        Self(match (machine.name(), machine.kind()) {
            (Some(name), _) => format!("{name} is this machine"),
            (None, Kind::Link) => "that link is for this machine".to_owned(),
            (None, _) => "that key is this machine's".to_owned(),
        })
    }
}

#[cfg(test)]
#[path = "through_serve_tests.rs"]
pub(crate) mod tests;
