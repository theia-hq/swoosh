//! `swoosh stop [me/<name>]`: stop swoosh serve on this machine, or on one of your own devices.
//!
//! Bare `stop` stops this machine's `serve` over the local control socket and prints the pid that answered;
//! `stop me/<name>` dials that device's member-only `control.stop` and, once admitted, triggers a graceful
//! teardown, the same stop a Ctrl-C or a `serve --expires` deadline gives. It stops the NODE (the node stops
//! serving); it does not power off the machine, and nothing here can start it again.
//!
//! The machine is only ever `me/<name>`, a name in the list of your devices. Every other shape (a bare word,
//! `me` alone, a contact, a key, a link, a path, two machines) is a usage error, exit 2, before any transport
//! binds: a path or a link at parse, the rest once the list of your devices is read. A bare person resolves
//! to that person's first device when dialed, so handing anything but a device of yours to the dial would
//! stop a machine nobody named. Your own name stops this machine locally, as bare `stop` does.
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
//! The one tolerant case is the teardown RACE: the stream open can fail because the node is already tearing
//! itself down in response to the request (the goal state), not because the dial was refused. On a
//! non-refusal stream-open failure the verb probes the peer for a bounded window: a peer that stays
//! unreachable is gone or stopping, so the stop is reported as completed; a peer that still accepts a
//! connection is live, so the original failure stands loudly (never masked).

use core::time::Duration;

use bifrost::{Discovery, Node, NodeId, Session as _, Transport};
use clap::Args;
use nauthy::{Link, Service};
use swoosh::contacts::{ContactRef, Contacts, ContactsStore, DeviceLabel, ME, Petname};
use swoosh::home::Home;
use swoosh::node_client::{ControlClient, NodeClient as _, control_error_report};
use swoosh::peer::{OwnDevice, Peer};
use swoosh::serve::{CONTROL_STOP_SERVICE, STOP_ACK};
use swoosh::transport::ReachArgs;
use tightbeam::identity::AsVerifyKey as _;
use tightbeam::tunnel::Connector;
use tokio::io::AsyncReadExt as _;

/// How long a failed control-stream open is probed before it reads as a completed stop. The node closes its
/// endpoint right after a graceful teardown, so an unreachable peer over this window is gone or stopping; a
/// live peer answers a probe connect at once. Bounded so a peer that is merely slow still fails loudly.
const STOP_PROBE_WINDOW: Duration = Duration::from_secs(3);

/// The delay between probe dials inside [`STOP_PROBE_WINDOW`].
const STOP_PROBE_INTERVAL: Duration = Duration::from_millis(100);

/// The refusal for a link or a path where the machine goes: a link carries no right to stop a machine.
pub const A_LINK_STOPS_NOTHING: &str = "a link cannot stop a machine; only your own devices can";

/// The refusal for more than one machine.
pub const ONE_MACHINE: &str = "swoosh stop takes one machine";

/// Stop swoosh serve here, or on one of your own devices.
#[derive(Debug, Args)]
pub struct StopCmd {
    /// One of your own devices; none stops this machine
    #[arg(value_name = "me/<name>", value_parser = Aim::parse)]
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
}

impl Aim {
    /// The value parser: every shape is sorted for [`resolve`](Self::resolve), a link or a path into
    /// [`Link`](Self::Link) without being opened or parsed.
    fn parse(text: &str) -> Result<Self, String> {
        if swoosh::peer::is_path(text)
            || swoosh::link::is_prefixed(text)
            || swoosh::link::looks_bare(text)
        {
            return Ok(Self::Link);
        }
        if let Some(key) = swoosh::peer::raw_key(text).map_err(|error| error.to_string())? {
            return Ok(Self::Key(key));
        }
        let reference = text
            .parse::<ContactRef>()
            .map_err(|error| error.to_string())?;
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
                if yours.names(word.as_str()) {
                    Err(Usage(format!(
                        "swoosh stop takes one of your machines: swoosh stop {ME}/{word}"
                    )))
                } else if yours.contacts.devices(&word).is_some()
                    || yours.contacts.signet(&word).is_some()
                {
                    Err(Usage(format!(
                        "you can stop only your own machines; {word} is a contact"
                    )))
                } else {
                    Err(Usage(match yours.first() {
                        Some(example) => {
                            format!("swoosh stop takes one of your machines, like {example}")
                        }
                        None => "swoosh stop takes one of your machines".to_owned(),
                    }))
                }
            }
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
            Self::Key(key) => Err(Usage(match yours.contacts.saved_at(&key) {
                Some(name) if name.petname().as_str() == ME && name.device().is_some() => {
                    format!("name the machine: swoosh stop {name}")
                }
                _ => "that key is not one of your machines".to_owned(),
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
/// this machine, and the names it lists as revoked.
struct Yours {
    /// The book, `me` derived from the list of your devices.
    contacts: Contacts,
    /// The name the list gives this machine, if it gives one.
    own: Option<DeviceLabel>,
    /// The names of the devices the list revokes.
    revoked: Vec<DeviceLabel>,
}

impl Yours {
    /// Read the list of your devices this home holds. Local files only; nothing is written, nothing dials.
    async fn read(home: &Home) -> eyre::Result<Self> {
        let contacts = ContactsStore::open(home).await?.contacts().clone();
        let own = swoosh::renewal::own_label(home).await;
        // The same read the book's `me` is derived from: a pin that cannot be read, or a list that does not
        // verify under it, holds no devices and so revokes none either.
        let revoked = match swoosh::config::load_signet(home).await {
            Ok(Some(pin)) => pin
                .verify_key()
                .ok()
                .and_then(|pin| swoosh::roster::held(home, pin))
                .map(|list| {
                    list.revoked_devices()
                        .iter()
                        .map(|device| device.label.clone())
                        .collect()
                })
                .unwrap_or_default(),
            Ok(None) | Err(_) => Vec::new(),
        };
        Ok(Self {
            contacts,
            own,
            revoked,
        })
    }

    /// Your devices' names, `me/<name>`, in label order.
    fn devices(&self) -> Vec<String> {
        Petname::stored(ME)
            .ok()
            .and_then(|me| {
                self.contacts
                    .devices(&me)
                    .map(|devices| devices.map(|(label, _)| format!("{ME}/{label}")).collect())
            })
            .unwrap_or_default()
    }

    /// Whether `word` is one of your devices' names.
    fn names(&self, word: &str) -> bool {
        self.devices()
            .iter()
            .any(|name| name.strip_prefix("me/") == Some(word))
    }

    /// The first of your devices, to show the shape a machine takes.
    fn first(&self) -> Option<String> {
        self.devices().into_iter().next()
    }

    /// The detail line that lists your devices, or says this machine holds no list of them.
    fn listed(&self) -> String {
        let devices = self.devices();
        if devices.is_empty() {
            "This machine holds no list of your devices.".to_owned()
        } else {
            format!("Yours: {}.", devices.join(", "))
        }
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
    pub async fn run_local(self, home: &Home) -> eyre::Result<Option<StopDevice>> {
        let target = match self.machine {
            None => Target::Here,
            Some(aim) => aim.resolve(&Yours::read(home).await?)?,
        };
        match target {
            Target::Here => {
                // The reach trio binds a transport and seeds discovery for a PEER; stopping this machine binds
                // neither, so the flags are refused by name rather than silently ignored (I.3, B4).
                swoosh::reaching::reject_bare_reach(&self.reach)?;
                let client = ControlClient::resolve(home).map_err(control_error_report)?;
                eprintln!("{}", stop_resolved(&client).await?);
                Ok(None)
            }
            Target::Device { device, node } => {
                self.reach.reject_unused_reach()?;
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
        // badge. On admission the node cancels its teardown token and writes one ack byte; a refusal maps to
        // a loud stream error here. The connect chain can carry the peer's text (the reason it gave for
        // closing), so it goes only to the log, escaped, never onto the line.
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
        let (writer, mut reader) = match session.open_bi().await {
            Ok(stream) => stream,
            // A refusal is a LIVE peer saying no, so it is never raced away.
            Err(bifrost::Error::Refused(_)) => {
                eyre::bail!("{device} refused: only your own devices can stop it")
            }
            // The stream-open can lose the race with the very teardown the request triggered: the node
            // cancels its token, closes its endpoint, and this side sees a transport failure instead of the
            // torn ack tolerated below. Any such failure probes for the peer going down, and the original
            // error stands if it stays live.
            Err(error) => {
                if !peer_gone(node, self.node, STOP_PROBE_WINDOW).await {
                    tracing::debug!(
                        error = %swoosh::escape::Escaped(&error.to_string()),
                        "the stop's stream failed and the device is still up"
                    );
                    eyre::bail!("could not stop {device}\n  Nothing was stopped.");
                }
                return Ok(stopped_line(device, self.node));
            }
        };

        // Read the node's ack byte: proof the stop was actioned, not merely that the dial was admitted. The
        // node closes right after, so an unexpected EOF before the ack is itself the confirmation the node
        // is going down; only a wrong byte on a live stream is a surprise worth naming.
        let mut ack = [0u8; 1];
        match reader.read_exact(&mut ack).await {
            Ok(_) if ack[0] == STOP_ACK => {}
            Ok(_) => eyre::bail!("stopped {device}, but it sent an unexpected control reply"),
            // The node tore the stream down as it stopped: expected on a successful stop.
            Err(_eof) => {}
        }
        drop(writer);

        Ok(stopped_line(device, self.node))
    }
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
/// form only confirms which key), then that nothing here can start it again.
fn stopped_line(device: &OwnDevice, node: NodeId) -> String {
    format!(
        "Stopped {device} ({}).\nNothing here can start it again: it serves when swoosh serve runs on {}.\n",
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
