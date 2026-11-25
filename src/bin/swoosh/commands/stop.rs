//! `swoosh stop [me/<name>]`: stop swoosh serve on this machine, or on one of your own devices.
//!
//! Bare `stop` stops this machine's `serve` over the local control socket and prints the pid that answered;
//! `stop me/<name>` asks that device's member-only `control.serve` for a stop and, once answered, the device
//! runs a graceful teardown, the same stop a Ctrl-C or a `serve --expires` deadline gives. It stops the NODE
//! (the node stops serving); it does not power off the machine, and it serves again when `swoosh serve`
//! next runs there.
//!
//! The machine is only ever `me/<name>`, a name in the list of your devices. Every other shape (a bare word,
//! `me` alone, a contact, a key, a link, a path, two machines) is a usage error, exit 2, before any transport
//! binds: a path or a link at parse, the rest once the list of your devices is read, so only a device of
//! yours ever reaches the dial. Your own name stops this machine locally, as bare `stop` does.
//!
//! `control.serve` is MEMBER-only, not merely family-gated: the node admits a whole-node membership badge
//! (your own devices), and refuses a delegated slip at the route's member floor with the same uniform
//! refusal a gate miss gives, before any `Response::Ok`. Any of your own devices can stop any other, which
//! is correct for a CI teardown; the stopped node says which one did.
//!
//! A refusal is a LOUD typed error, never a silent success: if the node's gate does not admit this caller,
//! opening the stream fails and `stop` reports the refusal and exits non-zero.
//!
//! The request is one byte, written on the opened stream and never with the open, so an open that fails
//! carried no request and nothing was stopped, whatever failed. `Stopped` prints only on the node's `Done`.
//! Once the byte may have left, every other ending (another answer aside) is unconfirmed: a stream that
//! breaks or ends before an answer, or one that sends none within [`ANSWER_DEADLINE`].
//!
//! The stop is one body on both paths: by its own bind, or as one Open through `swoosh serve` when it
//! runs here. Either way the request rides a connection of its own, so it goes out at most once.

use core::time::Duration;
use std::io;

use bifrost::NodeId;
use clap::Args;
use swoosh::contacts::{ContactRef, Contacts, ContactsStore, DeviceLabel, ME, Petname};
use swoosh::credential::Credential;
use swoosh::escape::Escaped;
use swoosh::home::{Home, ProcessId};
use swoosh::node_client::{ControlClient, control_error_report};
use swoosh::peer::{Machine, OwnDevice, Peer};
use swoosh::peers::{Hints, OpenError};
use swoosh::root_key::RootKey;
use swoosh::roster::RosterDoc;
use swoosh::serve::CONTROL_SERVE_SERVICE;
use swoosh::serve::control::{Answer, Request};
use swoosh::serve::control_codec::{OpenLane, OpenRefusal};
use swoosh::streams::{Ask, Opened, StreamSource, Unopened};
use swoosh::transport::{BareReachFlag, ReachArgs};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use crate::commands::route::Route;

/// How long the stop waits for the device once its stream is open: the request's write, the one byte back,
/// and the close. A device answers at once, so this bounds only a stalled `serve` or a device that keeps
/// the stream open and says nothing, which would otherwise hold `stop` (and a CI teardown) forever.
pub const ANSWER_DEADLINE: Duration = Duration::from_secs(10);

/// The refusal for a link or a path where the machine goes: a link carries no right to stop a machine.
pub const A_LINK_STOPS_NOTHING: &str = "a link cannot stop a machine; only your own devices can";

/// The refusal for more than one machine.
pub const ONE_MACHINE: &str = "swoosh stop takes one machine";

/// The machine's argument id, which the composition root widens for its second parse.
pub const MACHINE: &str = "machine";

/// The detail line under a refusal when this machine holds no list of your devices to show.
const KNOWS_NONE: &str = "This machine knows none of your devices.";

/// Stop swoosh serve here or on one of your own devices.
#[derive(Debug, Args)]
pub struct StopCmd {
    /// One of your own devices; leave it out to stop this machine
    #[arg(id = MACHINE, value_name = "me/<name>", value_parser = Aim::parse)]
    pub machine: Option<Aim>,
    #[command(flatten)]
    pub reach: ReachArgs,
}

/// What `stop` was given, sorted by shape at the clap boundary: the device it names, or which refusal fits.
/// A link or a path is refused as the line is parsed, before the home is read; every other refusal once the
/// list of your devices is read.
#[derive(Debug, Clone)]
pub enum Aim {
    /// `me/<name>`: a device of yours, if the list holds the name.
    Device(OwnDevice),
    /// `me` alone, which names no one machine.
    Me,
    /// A bare word: one of your device names typed without `me/`, a contact, or neither.
    Word(Petname),
    /// `<person>/<name>`: a machine of someone else's.
    Theirs(ContactRef),
    /// A key, which a person names by its name.
    Key(NodeId),
    /// A root's key (`root:ed01…`), which vouches for machines and is none of them. Never echoed.
    Root(RootKey),
    /// A `swoosh:` link or a path, which carries no right to stop a machine. Never opened or parsed, so
    /// the refusal neither reads a file nor prints the link's token back.
    Link,
    /// Text that is no name, no key and no link. Kept as nothing, so its refusal cannot print it back.
    NotAName,
}

impl Aim {
    /// The value parser: every shape is sorted for [`resolve`](Self::resolve), and none is refused here.
    /// clap prints the typed value back with any value error, and a damaged link's token is still a
    /// token, so this parser cannot fail: what is not a machine is refused later with a fixed line.
    /// Any text holding a dot is a link, never opened or parsed: no name, key or `me/<name>` holds one.
    pub fn parse(text: &str) -> Result<Self, core::convert::Infallible> {
        if text.contains('.') || swoosh::peer::is_path(text) || swoosh::link::is_prefixed(text) {
            return Ok(Self::Link);
        }
        if let Ok(root) = text.parse::<RootKey>() {
            return Ok(Self::Root(root));
        }
        let Ok(key) = swoosh::peer::raw_key(text) else {
            return Ok(Self::NotAName);
        };
        if let Some(key) = key {
            return Ok(Self::Key(key));
        }
        let Ok(reference) = text.parse::<ContactRef>() else {
            return Ok(Self::NotAName);
        };
        if let Some(device) = OwnDevice::of(&reference) {
            return Ok(Self::Device(device));
        }
        Ok(match reference.device() {
            Some(_) => Self::Theirs(reference),
            None if reference.petname().as_str() == ME => Self::Me,
            None => Self::Word(reference.petname().clone()),
        })
    }

    /// The machine this names against `yours`: this one, another of your devices, or the usage error that
    /// fits. Only a `me/<name>` the list holds ever reaches a dial; every other shape refuses here.
    fn resolve(self, yours: &Yours) -> Result<Target, Usage> {
        match self {
            Self::Device(device) => {
                // A name the list holds now wins over a revoked device that once had it.
                let Some(node) = device.key(&yours.contacts) else {
                    return Err(Usage(if yours.revoked.contains(device.label()) {
                        format!("{device} was revoked")
                    } else {
                        format!("you have no machine {device}\n  {}", yours.listed())
                    }));
                };
                if yours.own.as_ref() == Some(device.label()) {
                    return Ok(Target::Here);
                }
                Ok(Target::Device { device, node })
            }
            Self::Me => Err(Usage(format!("which machine?\n  {}", yours.listed()))),
            Self::Word(word) => {
                let Usage(refusal) = if yours.names(&word) {
                    Usage(format!(
                        "swoosh stop takes one of your machines: swoosh stop {ME}/{word}"
                    ))
                } else if yours.contacts.devices(&word).is_some()
                    || yours.contacts.signet(&word).is_some()
                {
                    Usage(format!(
                        "you can stop only your own machines; {word} is a contact"
                    ))
                } else {
                    yours.takes_one()
                };
                // A word this machine serves may be a service the person meant to stop: name the act that
                // does that here.
                Err(Usage(if yours.serves(&word) {
                    format!("{refusal}\n  To turn {word} off here:\n    swoosh service off {word}")
                } else {
                    refusal
                }))
            }
            Self::NotAName => Err(yours.takes_one()),
            Self::Theirs(reference) => {
                let person = reference.petname();
                Err(Usage(
                    if yours.contacts.devices(person).is_some()
                        || yours.contacts.signet(person).is_some()
                    {
                        format!("you can stop only your own machines; {person} is a contact")
                    } else {
                        format!(
                            "you can stop only your own machines; {reference} is not one of them"
                        )
                    },
                ))
            }
            Self::Link => Err(Usage(A_LINK_STOPS_NOTHING.to_owned())),
            // `stop` takes only your machines, so the refusal lists them, whosever root it is.
            Self::Root(root) => {
                let whose = if yours.contacts.your_root() == Some(root.key()) {
                    "your root key"
                } else {
                    "a root key"
                };
                Err(Usage(format!(
                    "that is {whose}, not a machine's key\n  {}",
                    yours.listed()
                )))
            }
            // Looked up among your devices only: the book may also hold the key under a contact's name.
            Self::Key(key) => Err(Usage(match yours.mine().find(|(_, node)| *node == key) {
                Some((device, _)) => format!("name the machine: swoosh stop {device}"),
                None => "that key is not one of your machines".to_owned(),
            })),
        }
    }
}

/// What `stop` resolved to: this machine, or another of your devices to dial.
#[derive(Debug)]
enum Target {
    /// This machine: stopped over the local control socket.
    Here,
    /// Another of your devices: stopped over its `control.serve`.
    Device {
        /// Its name, for every line.
        device: OwnDevice,
        /// Its key in the list of your devices.
        node: NodeId,
    },
}

/// What a machine argument is resolved against: the list of your devices this home holds, the name it gives
/// this machine, the names it lists as revoked, and the services this machine's list holds.
struct Yours {
    /// The book, `me` derived from the list of your devices.
    contacts: Contacts,
    /// The name the list gives this machine, if it gives one.
    own: Option<DeviceLabel>,
    /// The names of the devices the list revokes.
    revoked: Vec<DeviceLabel>,
    /// The names this machine's list of services holds, for a refusal to say how to turn one off; empty
    /// when `serve.toml` does not read, which only loses that line.
    served: Vec<String>,
}

impl Yours {
    /// Read the list of your devices this home holds. Local files only; nothing is written, nothing dials.
    /// One open of the book reads the list `me` is derived from, and what it revokes comes from that same
    /// list; this machine's own name is the one the list gives its key.
    async fn read(home: &Home) -> eyre::Result<Self> {
        let store = ContactsStore::open(home).await?;
        let revoked = store
            .list()
            .map(RosterDoc::revoked_devices)
            .unwrap_or_default()
            .iter()
            .map(|device| device.label.clone())
            .collect();
        let contacts = store.contacts().clone();
        let file = keystore::KeyFile::new(home.key());
        let key = file
            .load()
            .ok()
            .flatten()
            .and_then(|stored| swoosh::identity::key_of(&file, &stored).ok());
        let own = key.and_then(|key| {
            contacts
                .mine()
                .find(|(_, node)| **node == key)
                .map(|(label, _)| label.clone())
        });
        // Read as a bare `serve` reads the list, so a hand-written `ping` is served here as it is there; a
        // list `serve` refuses serves nothing, and the hint stays quiet.
        let served = swoosh::serve_toml::ServeToml::read(home)
            .ok()
            .and_then(|file| swoosh::serve::Started::bare(&file).ok())
            .map(|started| started.names())
            .unwrap_or_default();
        Ok(Self {
            contacts,
            own,
            revoked,
            served,
        })
    }

    /// Whether `word` names a service this machine's list holds.
    fn serves(&self, word: &Petname) -> bool {
        self.served.iter().any(|name| name == word.as_str())
    }

    /// Your devices and their keys, in label order.
    fn mine(&self) -> impl Iterator<Item = (OwnDevice, NodeId)> + '_ {
        self.contacts
            .mine()
            .map(|(label, node)| (OwnDevice::from(label.clone()), *node))
    }

    /// Whether `word` is one of your devices' names.
    fn names(&self, word: &Petname) -> bool {
        self.contacts
            .mine()
            .any(|(label, _)| label.as_str() == word.as_str())
    }

    /// The detail line that lists your devices, or says this machine knows none of them.
    fn listed(&self) -> String {
        let devices: Vec<OwnDevice> = self.mine().map(|(device, _)| device).collect();
        listed(&devices)
    }

    /// The refusal for a word that names nothing of yours: the shape a machine takes, shown by your first
    /// device, or, with none known, that this machine knows none of them.
    fn takes_one(&self) -> Usage {
        Usage(match self.mine().next() {
            Some((example, _)) => format!("swoosh stop takes one of your machines, like {example}"),
            None => format!("swoosh stop takes one of your machines\n  {KNOWS_NONE}"),
        })
    }
}

/// The detail line under a refusal that lists `devices`, your devices, or says this machine knows none of
/// them: the one listing every verb's `which machine?` prints.
pub fn listed(devices: &[OwnDevice]) -> String {
    if devices.is_empty() {
        KNOWS_NONE.to_owned()
    } else {
        let names: Vec<String> = devices.iter().map(ToString::to_string).collect();
        format!("Yours: {}.", names.join(", "))
    }
}

/// A usage error found once the list of your devices is read: exit 2, as clap's own are, before any
/// transport binds.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct Usage(pub String);

impl StopCmd {
    /// Everything before a dial: resolve the machine against the list of your devices, then either stop this
    /// machine over its control socket (bare, or your own name) and return `None`, or return the device to
    /// stop over its `control.serve`. Runs before any transport is composed, so a refused shape binds nothing.
    /// `typed` is a reach flag typed on the command line, which stopping this machine refuses.
    pub async fn run_local(
        self,
        home: &Home,
        typed: Option<BareReachFlag>,
    ) -> eyre::Result<Option<StopDevice>> {
        let target = match self.machine {
            None => Target::Here,
            Some(aim) => aim.resolve(&Yours::read(home).await?)?,
        };
        match target {
            Target::Here => {
                // The reach flags bind a transport and find a machine; stopping this machine does neither,
                // so a typed one is a usage error rather than silently ignored. A variable is the shell's
                // standing setting, read by the verbs that reach, so it is ignored here.
                if let Some(flag) = typed {
                    return Err(Usage(flag.to_string()).into());
                }
                let client = ControlClient::resolve(home).map_err(control_error_report)?;
                eprintln!("{}", stop_resolved(&client).await?);
                Ok(None)
            }
            Target::Device { device, node } => {
                self.reach
                    .reject_unused_reach()
                    .map_err(|unused| Usage(unused.to_string()))?;
                Ok(Some(StopDevice {
                    peer: Peer::Raw(node),
                    device,
                    node,
                    reach: self.reach,
                }))
            }
        }
    }
}

/// Request a local stop and format its confirmation using only the listener PID returned by that
/// exchange. Do not use a resolve-time PID or reread the record after teardown.
async fn stop_resolved(client: &ControlClient) -> eyre::Result<String> {
    let pid = client
        .stop_attributed()
        .await
        .map_err(control_error_report)?;
    Ok(stop_line(pid))
}

/// `stop me/<name>` for another of your devices, resolved: ask its member-only `control.serve` for a
/// graceful stop.
#[derive(Debug)]
pub struct StopDevice {
    /// The device as dialed, for the stale-list exchange beside the stop.
    peer: Peer,
    /// Its name, for every line.
    device: OwnDevice,
    /// Its key in the list of your devices.
    node: NodeId,
    /// The reach flags.
    reach: ReachArgs,
}

impl swoosh::reaching::Reaching for StopDevice {
    fn reach_args(&self) -> &ReachArgs {
        &self.reach
    }

    /// The device this verb dials, for the stale-list exchange after it runs.
    fn dialed(&self) -> Option<&Peer> {
        Some(&self.peer)
    }

    fn identity(&self) -> swoosh::identity::Identity {
        self.bind_role().identity()
    }

    /// Dialing, and what it dials as. It reaches a device and never accepts connections under the home key,
    /// so its bind must not write the key's address record (0.9.0 F1). It presents this device's membership
    /// badge, rooted at the dialing key: only one of your devices may stop another.
    fn bind_role(&self) -> swoosh::reaching::BindRole {
        swoosh::reaching::BindRole::Dialing(self.credential())
    }
}

impl StopDevice {
    /// What this run dials as: this home's standing, as it reads at the open. Never a link: a stop goes
    /// only from one of your devices to another.
    pub(crate) fn credential(&self) -> Credential {
        Credential::Family { present: None }
    }

    /// Stop the device over one `control.serve` stream from `source`, on a connection of its own, its lines
    /// on `err`, each outcome worded by `route` where `stop` has no line of its own. The request is written
    /// once the stream is open; the node answers one byte and, on `Done`, waits for this side to close
    /// before it cancels its teardown token. A node that does not admit this caller refuses LOUDLY here,
    /// never a silent no-op.
    ///
    /// The connection is its own, never a held session: an open on a held one that fails is retried on a
    /// fresh dial, which would send the request a second time, and could report the device unreachable
    /// after a request already left.
    ///
    /// # Errors
    ///
    /// The run's line: unreached, refused, not stopped, not yet, unconfirmed, or the route's for an outcome
    /// that says nothing of the device.
    pub(crate) async fn stop(
        &self,
        source: impl StreamSource,
        route: &Route<'_>,
        machine: &Machine,
        err: &mut impl io::Write,
    ) -> eyre::Result<()> {
        // The open carries no request: the stop byte is written below, only on the stream an open returned.
        // So an open that fails, however late, stopped nothing.
        let ask = Ask {
            peer: self.node,
            hints: Hints::NONE,
            service: CONTROL_SERVE_SERVICE.parse()?,
            lane: OpenLane::Isolated,
            slip: None,
        };
        let Opened {
            mut write,
            mut read,
            ..
        } = match source.open(&ask).await {
            Ok(opened) => opened,
            Err(unopened) => return Err(self.unopened(unopened, route, machine).await),
        };
        let device = &self.device;

        // The request, then the answer, with this side still open: the node stops only once it sees this
        // end, so its teardown cannot drop the answer in flight. Bounded as one, since from the first write
        // on the byte may have left and only an answer tells. The close below takes what is left of the
        // same bound, so the whole stop after the open is bounded once.
        let deadline = tokio::time::Instant::now() + ANSWER_DEADLINE;
        let answer = tokio::time::timeout_at(deadline, async {
            write.write_all(&[Request::Stop.encode()]).await?;
            write.flush().await?;
            let mut answer = [0u8; 1];
            read.read_exact(&mut answer).await?;
            Ok(answer[0])
        })
        .await
        .unwrap_or_else(|_elapsed| {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "the device sent no answer in time",
            ))
        });
        // Shut down, not only dropped, since a dropped writer does not end the stream on every transport.
        // Any end counts there, so a close that fails or is lost on the way still stops it within its bound.
        // Under the deadline too: a close that waits on a peer granting nothing would otherwise hold `stop`
        // past its bound. Past the deadline it is still tried once, then the writer is dropped.
        let _ = tokio::time::timeout_at(deadline, write.shutdown()).await;
        confirmed(answer, device)?;
        write!(err, "{}", stopped_line(device, self.node))?;
        Ok(())
    }

    /// The line an open that gave no stream ends the run with. The request rides only an opened stream, so
    /// no outcome here sent it: the device's refusal and an unreached device keep their own lines, every
    /// other failure of the open says nothing was stopped, and an outcome that says nothing of the device
    /// prints `route`'s line.
    async fn unopened(
        &self,
        unopened: Unopened,
        route: &Route<'_>,
        machine: &Machine,
    ) -> eyre::Report {
        let device = &self.device;
        // The chain can carry the peer's text (the reason it gave for closing), so it goes only to the log,
        // escaped, never onto the line.
        tracing::debug!(
            unopened = %Escaped(&format!("{unopened:?}")),
            "the stop's stream was not opened"
        );
        match unopened {
            Unopened::Refused(OpenRefusal::Peer(_)) => {
                eyre::eyre!("{device} refused: only your own devices can stop it")
            }
            Unopened::Own(OpenError::Unreachable(_))
            | Unopened::Refused(OpenRefusal::Unreachable(_)) => unreachable(device),
            Unopened::Own(OpenError::Timeout | OpenError::Open(_))
            | Unopened::Refused(
                OpenRefusal::Timeout | OpenRefusal::Broken(_) | OpenRefusal::PeerUnreadable(_),
            ) => eyre::eyre!("could not stop {device}\n  Nothing was stopped."),
            unopened @ (Unopened::Own(OpenError::Busy)
            | Unopened::Refused(
                OpenRefusal::Busy | OpenRefusal::StandingEnded | OpenRefusal::NotHere,
            )
            | Unopened::Home(_)
            | Unopened::ServeError(_)
            | Unopened::ServeGone
            | Unopened::Skew
            | Unopened::Malformed(_)
            | Unopened::Control(_)) => route.line(unopened, machine).await,
        }
    }
}

/// Whether the node's answer proves the stop: only `Done` does. `NotYet` is a machine still in its first
/// sync, which stopped nothing. Any other byte, a stream that ended or broke before an answer, or no answer
/// in time proves nothing, so the device may still be serving. A conforming node never ends the stream
/// cleanly before its answer (an unanswered stream is reset), so a clean end is no proof either.
fn confirmed(answer: io::Result<u8>, device: &OwnDevice) -> eyre::Result<()> {
    match answer.map(Answer::decode) {
        Ok(Some(Answer::Done)) => Ok(()),
        Ok(Some(Answer::NotYet)) => eyre::bail!(
            "{device} has just started; it cannot be stopped from here yet\n  {} is still syncing with your devices. Try again in a minute.",
            device.label()
        ),
        Ok(Some(Answer::BadRequest) | None) => {
            eyre::bail!("{device} sent an unknown reply to the stop; it may still be serving")
        }
        Err(error) => {
            tracing::debug!(
                error = %Escaped(&error.to_string()),
                "the stop's stream ended before the node answered"
            );
            Err(unconfirmed(device))
        }
    }
}

/// The failure when the device may have stopped and nothing proves it did.
fn unconfirmed(device: &OwnDevice) -> eyre::Report {
    eyre::eyre!("could not confirm that {device} stopped; it may still be serving")
}

/// The refusal when the device did not answer: nothing was stopped.
fn unreachable(device: &OwnDevice) -> eyre::Report {
    eyre::eyre!(
        "could not reach {device}: it is offline or not running swoosh serve\n  Nothing was stopped."
    )
}

/// The two lines a stopped device prints: its name and short key (the line names the machine, so the short
/// form only confirms which key), then when it serves again.
fn stopped_line(device: &OwnDevice, node: NodeId) -> String {
    format!(
        "Stopped {device} ({}).\nIt serves again when swoosh serve next runs on {}.\n",
        swoosh::credential::short(&node),
        device.label(),
    )
}

/// Format the local stop confirmation. The PID identifies the listener attributed on the stop
/// connection, not proof that the process has exited.
fn stop_line(pid: ProcessId) -> String {
    format!("Stopped swoosh serve here (pid {pid}).")
}

#[cfg(test)]
#[path = "stop_tests.rs"]
mod stop_tests;
