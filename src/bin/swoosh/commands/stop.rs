//! `swoosh stop [me/<name>]`: stop swoosh serve on this machine, or on one of your own devices.
//!
//! Bare `stop` stops this machine's `serve` over the local control socket and prints the pid that answered;
//! `stop me/<name>` dials that device's member-only `control.stop` and, once admitted, triggers a graceful
//! teardown, the same stop a Ctrl-C or a `serve --expires` deadline gives. It stops the NODE (the node stops
//! serving); it does not power off the machine, and it serves again when `swoosh serve` next runs there.
//!
//! The machine is only ever `me/<name>`, a name in the list of your devices. Every other shape (a bare word,
//! `me` alone, a contact, a key, a link, a path, two machines) is a usage error, exit 2, before any transport
//! binds: a path or a link at parse, the rest once the list of your devices is read, so only a device of
//! yours ever reaches the dial. Your own name stops this machine locally, as bare `stop` does.
//!
//! `control.stop` is MEMBER-only, not merely family-gated: the node admits a whole-node membership badge
//! (your own devices), and refuses a delegated slip at the route's member floor with the same uniform
//! refusal a gate miss gives, before any `Response::Ok`. Any of your own devices can stop any other, which
//! is correct for a CI teardown; the stopped node says which one did. Hardening the lifecycle further (an
//! arm->confirm nonce + a single-use device-bound destroy-cap, ideally owner-only so another fleet device
//! cannot stop the node) is a follow-up, and it needs a security review before `control.stop` is trusted
//! across a multi-device fleet.
//!
//! A refusal is a LOUD typed error, never a silent success: if the node's gate does not admit this caller,
//! opening the control stream fails and `stop` reports the refusal and exits non-zero.
//!
//! `Stopped` prints only on what proves the stop: the node's ack byte, or the stream it admitted closing
//! cleanly as the node goes down. A stream open that fails for any other reason never saw the admission,
//! so it cannot tell a node tearing itself down for this request from a path that dropped it: the verb
//! probes the peer for a bounded window, and a peer still live has stopped nothing, while a peer gone
//! may have stopped or may only be out of reach, and the line says the stop is unconfirmed.

use core::time::Duration;
use std::io;

use bifrost::{Discovery, Node, NodeId, Session as _, Transport};
use clap::Args;
use nauthy::{Link, Service};
use swoosh::contacts::{ContactRef, Contacts, ContactsStore, DeviceLabel, ME, Petname};
use swoosh::home::Home;
use swoosh::node_client::{ControlClient, NodeClient as _, control_error_report};
use swoosh::peer::{OwnDevice, Peer};
use swoosh::roster::RosterDoc;
use swoosh::serve::{CONTROL_STOP_SERVICE, STOP_ACK};
use swoosh::transport::{BareReachFlag, ReachArgs};
use tightbeam::tunnel::Connector;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

/// How long a failed control-stream open is probed, to tell a live peer (nothing was stopped) from one that
/// went away (the stop is unconfirmed). A live peer answers a probe connect at once; an unreachable one over
/// this window is gone, stopping, or out of reach, and the probe cannot tell which.
const STOP_PROBE_WINDOW: Duration = Duration::from_secs(3);

/// The delay between probe dials inside [`STOP_PROBE_WINDOW`].
const STOP_PROBE_INTERVAL: Duration = Duration::from_millis(100);

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
    /// Another of your devices: stopped over its `control.stop`.
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
            .and_then(|file| swoosh::serve::Started::bare(&file, &home.serve_toml()).ok())
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
    /// stop over its `control.stop`. Runs before any transport is composed, so a refused shape binds nothing.
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

/// Stop this machine's `serve` over the resolved local client: the line confirming it, with the pid the
/// client read from the resident's lock at resolve. Split from the resolve so a test drives the verb against
/// the local socket backend without resolving the process-global runtime root.
async fn stop_resolved(client: &ControlClient) -> eyre::Result<String> {
    let pid = client.pid();
    client.stop().await.map_err(control_error_report)?;
    Ok(stop_line(pid))
}

/// `stop me/<name>` for another of your devices, resolved: reach its member-only `control.stop` and trigger
/// a graceful stop.
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
        swoosh::reaching::BindRole::Dialing(swoosh::credential::Credential::Family {
            present: None,
        })
    }

    /// Uniform dispatch: stop the device with the resolved badge; the rest of the context is unused.
    async fn run<T: Transport, D: Discovery>(
        self,
        node: &Node<T, D>,
        ctx: swoosh::reaching::ReachCtx<'_>,
    ) -> eyre::Result<()>
    where
        <T::Session as bifrost::Session>::Write: Send + 'static,
        <T::Session as bifrost::Session>::Read: Send + 'static,
    {
        eprint!(
            "{}",
            self.run_stop(node, ctx.present, ctx.membership).await?
        );
        Ok(())
    }
}

impl StopDevice {
    /// Reach the device's member-only `control.stop` service and trigger a graceful stop. Presents the
    /// resolved `present` (this device's membership badge) so the gate rules on the stream; only a
    /// whole-node member passes the route's member floor, and a node that does not admit this caller refuses
    /// LOUDLY here, never a silent no-op. The lines saying it stopped, once it has.
    async fn run_stop<T: Transport, D: Discovery>(
        self,
        node: &Node<T, D>,
        present: Option<Link>,
        membership: Option<Link>,
    ) -> eyre::Result<String> {
        let connector =
            Connector::to_node(self.node, CONTROL_STOP_SERVICE.parse::<Service>()?, present);
        // Slot 2: a badge under a foreign fleet, only for a signet-bound slip in slot 1; a no-op here.
        let connector = match membership {
            Some(badge) => connector.with_membership(badge),
            None => connector,
        };
        let device = &self.device;

        // A service-scoped session whose one `open_bi` speaks the `control.stop` request and presents the
        // badge. On admission the node writes one ack byte and waits for this side to close before it
        // cancels its teardown token; a refusal maps to a loud stream error here. The connect chain can
        // carry the peer's text (the reason it gave for closing), so it goes only to the log, escaped, never
        // onto the line.
        let session = match connector.open_service(node).await {
            Ok(session) => session,
            Err(error) => {
                tracing::debug!(
                    error = %swoosh::escape::escaped_report(error),
                    "could not reach the device to stop"
                );
                return Err(unreachable(device));
            }
        };
        let (mut writer, mut reader) = match session.open_bi().await {
            Ok(stream) => stream,
            // A refusal is a LIVE peer saying no, so it is never raced away.
            Err(bifrost::Error::Refused(_)) => {
                eyre::bail!(
                    "{device} refused: only your own devices can stop it\n  If it has just started, try again in a minute."
                )
            }
            // Any other failure came before the admission, so this side cannot know whether the node
            // took the request: it may have lost the race with the very teardown the request triggered, or
            // the path may have dropped it. A peer still live after the probe has stopped nothing; a peer
            // gone is never reported stopped, only unconfirmed.
            Err(error) => {
                tracing::debug!(
                    error = %swoosh::escape::Escaped(&error.to_string()),
                    "the stop's stream failed"
                );
                if peer_gone(node, self.node, STOP_PROBE_WINDOW).await {
                    return Err(unconfirmed(device));
                }
                eyre::bail!("could not stop {device}\n  Nothing was stopped.");
            }
        };

        // Read the node's ack byte: proof the stop was actioned, not merely that the dial was admitted.
        let mut ack = [0u8; 1];
        let read = reader.read_exact(&mut ack).await;
        // Close this side the moment the ack is read: the node stops only once it sees this end, so its
        // teardown cannot drop the ack in flight. Shut down, not only dropped, since a dropped writer does
        // not end the stream on every transport. Any end counts there, so a close that fails or is lost on
        // the way still stops it within its bound.
        let _ = writer.shutdown().await;
        confirmed(read.map(|_| ack[0]), device)?;
        Ok(stopped_line(device, self.node))
    }
}

/// Whether the node's answer on the admitted control stream proves the stop: its ack byte, or the stream
/// closing cleanly before one, which an admitted stop does as the node goes down. A wrong byte, or a
/// stream broken any other way, proves nothing, so the device may still be serving.
fn confirmed(answer: io::Result<u8>, device: &OwnDevice) -> eyre::Result<()> {
    match answer {
        Ok(STOP_ACK) => Ok(()),
        Ok(_) => eyre::bail!("{device} sent an unknown reply to the stop; it may still be serving"),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(()),
        Err(error) => {
            tracing::debug!(
                error = %swoosh::escape::Escaped(&error.to_string()),
                "the stop's stream broke before the node answered"
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

/// Whether `dial` is unreachable (gone, or mid-teardown) over `window`: the liveness probe that tells a
/// lost teardown race from a live peer. A successful connect at ANY point means the peer is still live, so
/// it returns `false` immediately (the caller must not report a false success); a window with no successful
/// connect means the peer is gone, so it returns `true`. The probe session is dropped at once: this is a
/// liveness read, never a second stop attempt.
async fn peer_gone<T: Transport, D: Discovery>(
    node: &Node<T, D>,
    dial: NodeId,
    window: Duration,
) -> bool {
    let probing = async {
        loop {
            if node.connect(dial).await.is_ok() {
                return false;
            }
            tokio::time::sleep(STOP_PROBE_INTERVAL).await;
        }
    };
    // The window bounds the probe: a peer that never accepts a connect (a hung dial included) counts as
    // gone, which is the state the caller asked for.
    tokio::time::timeout(window, probing).await.unwrap_or(true)
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

/// The one line a completed self-stop prints. The pid comes from the resident's `serve.lock` read
/// at resolve (the same record the single-instance refusal names), so the line proves WHICH process
/// answered; a lock the resident had not written yet leaves the parenthetical off rather than
/// printing a blank or a guess.
fn stop_line(pid: Option<u32>) -> String {
    match pid {
        Some(pid) => format!("Stopped swoosh serve here (pid {pid})."),
        None => "Stopped swoosh serve here.".to_owned(),
    }
}

#[cfg(test)]
#[path = "stop_tests.rs"]
mod stop_tests;
