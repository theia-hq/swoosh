//! The exchange: how two devices of one root come to hold the same update.
//!
//! One exchange runs on one stream of the `control.sync` route every `serve` binds. The dialer names the
//! update it holds by its number and digest; the other side answers that it holds the same, that it holds a
//! newer one (and sends it), that the dialer should send its own, or that both hold another update at one
//! number (a fork), when each side takes the other's. Then each side passes on the fork it keeps, if any:
//!
//! ```text
//! dialer  -> 0x01 exchange, number (u64), digest (32 bytes, BLAKE3 of the update's bytes; zero for none yet)
//! server  -> 0x00 same, digest     (equal number, equal digest; the server's digest, zero off a device)
//!            0x01 mine, <update>   (server's number is higher)
//!            0x02 send yours       (dialer's number is higher, or server has none yet)
//!            0x03 both, <update>   (equal number, different digest: a fork)
//! dialer  -> <update>              (only after 0x02 or 0x03)
//! server  -> 0x00 folded | 0x02 refused | 0x03 fork recorded, <floor (u64)>   (only after 0x02)
//! dialer  -> <update>              (the fork it keeps; empty for none)
//! server  -> <update>              (the fork it keeps; empty for none)
//! ```
//!
//! An `<update>` is its length (u32) and its bytes. A `same` with digest zero ends the exchange: neither
//! side holds an update. Whatever side takes an update folds it ([`fold`](crate::roster::fold)). Whatever
//! side takes the other's kept fork folds it with [`fold_fork`](crate::roster::fold_fork), which adds its
//! revocations and never makes it the update held. A frame that breaks before the forks fails the
//! exchange; one that breaks while they pass leaves its answer as it is. A fold never starts another
//! exchange, so a root act is still the only thing that sends an update to more than one device.
//!
//! Only a device of a root, one that holds it or not, takes an update. Any other machine answers `same`
//! with digest zero and never asks for one, so a dialer holding an update never reads that answer as
//! "holds it". A device that cannot read its own standing closes the stream without answering.

use core::future::Future;
use core::time::Duration;
use std::collections::VecDeque;
use std::io;
use std::time::SystemTime;

use bifrost::{Discovery, Node, NodeId, Session as _, Transport};
use nauthy::VerifyKey;
use rand::seq::SliceRandom as _;
use tightbeam::identity::{AsNodeId as _, AsVerifyKey as _};
use tightbeam::tunnel::Connector;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

use crate::contacts::{ContactsStore, Petname};
use crate::home::{Home, HomeWrite};
use crate::roster::{Epoch, FoldError, Folded, MAX_ROSTER_BLOB, fold, fold_fork, read_held};
use crate::serve::SYNC_SERVICE;
use crate::standing::Standing;

/// How long one exchange may take.
pub const EACH: Duration = Duration::from_secs(5);

/// How old `synced` may be before a dialing verb exchanges on its connection.
pub const STALE: Duration = Duration::from_secs(60 * 60);

/// The dialer's one request.
const EXCHANGE: u8 = 0x01;

/// The server's answers to the request.
const SAME: u8 = 0x00;
const MINE: u8 = 0x01;
const SEND_YOURS: u8 = 0x02;
const BOTH: u8 = 0x03;

/// The server's answers to an update sent after `send yours`.
const FOLDED: u8 = 0x00;
const REFUSED: u8 = 0x02;
const FORK_RECORDED: u8 = 0x03;

/// The digest of "no update yet".
const NONE_YET: [u8; 32] = [0; 32];

/// How one exchange ended, from the dialer's side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    /// Both held the same update.
    Same,
    /// The other device held a newer update, and this machine took it.
    Took,
    /// The other device held another update at this machine's number: a fork, recorded here, and this
    /// machine's update sent to it.
    Forked,
    /// This machine held the newer update, and the other device took it.
    Gave,
    /// The other device held another update at the number of this machine's: a fork, recorded there.
    ForkRecorded {
        /// The number of the update the other device holds.
        floor: Epoch,
    },
    /// The other device refused this machine's update.
    Refused,
}

/// Why an exchange did not finish.
#[derive(Debug, thiserror::Error)]
pub enum ExchangeError {
    /// This machine is not a device of a root, so it has nothing to exchange.
    #[error("this machine is not one of your devices")]
    NotADevice,
    /// The standing could not be read.
    #[error(transparent)]
    Standing(#[from] crate::standing::StandingError),
    /// The stream failed.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// The other side said something the exchange does not.
    #[error("the other device answered out of turn")]
    Protocol,
    /// The other side answered `same` for an update it does not hold: it is not a device of this root.
    #[error("the other machine does not hold this list of your devices")]
    NotHeld,
    /// The other side sent more than any update can be.
    #[error("the other device sent more than any update can be")]
    TooLarge,
    /// The update taken could not be folded.
    #[error(transparent)]
    Fold(#[from] FoldError),
    /// The other device's gate did not admit this machine: the standing it presented was refused.
    #[error("the other device did not admit this machine")]
    NotAdmitted,
    /// The other device could not be reached.
    #[error(transparent)]
    Dial(#[from] eyre::Report),
}

/// The digest an exchange names `bytes` by: BLAKE3, or all zeros for no update.
pub fn digest(bytes: &[u8]) -> [u8; 32] {
    if bytes.is_empty() {
        NONE_YET
    } else {
        *blake3::hash(bytes).as_bytes()
    }
}

/// This machine's pin, when it is a device of a root.
async fn device_pin(home: &Home) -> Result<Option<VerifyKey>, ExchangeError> {
    Ok(match Standing::read(home).await? {
        Standing::Device { pin, .. } | Standing::HoldsRoot { pin, .. } => {
            Some(crate::standing::pin_key(home, pin)?)
        }
        Standing::Unpinned | Standing::InterruptedMint { .. } => None,
    })
}

/// The update this machine holds, its number and its bytes, or none yet.
fn held(home: &Home, pin: VerifyKey) -> (Epoch, Vec<u8>) {
    read_held(&home.devices(), pin).map_or((Epoch::UNVERSIONED, Vec::new()), |(doc, bytes)| {
        (doc.epoch(), bytes)
    })
}

/// Run one exchange as the dialer, over a stream already open to the other device's `control.sync`.
pub async fn exchange(
    home: &Home,
    reader: impl AsyncRead + Unpin,
    writer: impl AsyncWrite + Unpin,
) -> Result<Answer, ExchangeError> {
    let pin = device_pin(home).await?.ok_or(ExchangeError::NotADevice)?;
    let (number, bytes) = held(home, pin);
    dial_with(home, pin, number, &bytes, reader, writer).await
}

/// Run one exchange as the dialer naming and sending `bytes`, the update at `number`, rather than the one
/// this machine holds when it dials: a root act offers the update it cut, even if this machine has folded
/// a later one since.
pub async fn offer(
    home: &Home,
    number: Epoch,
    bytes: &[u8],
    reader: impl AsyncRead + Unpin,
    writer: impl AsyncWrite + Unpin,
) -> Result<Answer, ExchangeError> {
    let pin = device_pin(home).await?.ok_or(ExchangeError::NotADevice)?;
    dial_with(home, pin, number, bytes, reader, writer).await
}

/// The dialer's side of one exchange, naming and sending `bytes`, the update at `number`, as a device of
/// the root `pin`.
async fn dial_with(
    home: &Home,
    pin: VerifyKey,
    number: Epoch,
    bytes: &[u8],
    mut reader: impl AsyncRead + Unpin,
    mut writer: impl AsyncWrite + Unpin,
) -> Result<Answer, ExchangeError> {
    let mut request = Vec::with_capacity(1 + 8 + 32);
    request.push(EXCHANGE);
    request.extend_from_slice(&number.0.to_be_bytes());
    request.extend_from_slice(&digest(bytes));
    writer.write_all(&request).await?;
    writer.flush().await?;
    // The fork kept before this exchange: one taken in it came from the other device.
    let fork = kept_fork(home, pin);
    let answer = match reader.read_u8().await? {
        SAME => {
            let mut theirs = [0_u8; 32];
            reader.read_exact(&mut theirs).await?;
            if theirs != digest(bytes) {
                return Err(ExchangeError::NotHeld);
            }
            if theirs == NONE_YET {
                // Neither side holds an update.
                touch_synced(home).await;
                return Ok(Answer::Same);
            }
            Answer::Same
        }
        code @ (MINE | BOTH) => {
            let theirs = read_update(&mut reader).await?;
            if code == BOTH {
                write_update(&mut writer, bytes).await?;
            }
            match fold_here(home, &theirs).await? {
                // `mine` means the other device holds another update than the one named; this machine
                // holding it too (folded since it dialed) is still a take, never `same`.
                Folded::Newer | Folded::Same => Answer::Took,
                Folded::Fork { .. } => Answer::Forked,
                Folded::NotNewer => return Err(ExchangeError::Protocol),
            }
        }
        SEND_YOURS => {
            write_update(&mut writer, bytes).await?;
            match reader.read_u8().await? {
                FOLDED => Answer::Gave,
                REFUSED => Answer::Refused,
                FORK_RECORDED => Answer::ForkRecorded {
                    floor: Epoch(reader.read_u64().await?),
                },
                _ => return Err(ExchangeError::Protocol),
            }
        }
        _ => return Err(ExchangeError::Protocol),
    };
    // The updates have moved: forks that fail to pass leave the answer as it is.
    let forks = async {
        write_update(&mut writer, &fork).await?;
        writer.shutdown().await?;
        take_fork(home, &mut reader).await
    };
    if let Err(error) = forks.await {
        tracing::debug!(%error, "could not pass the forks kept in an exchange");
    }
    touch_synced(home).await;
    Ok(answer)
}

/// Answer one exchange as the server, over an admitted stream of `control.sync`.
pub async fn answer(
    home: &Home,
    mut reader: impl AsyncRead + Unpin,
    mut writer: impl AsyncWrite + Unpin,
) -> Result<(), ExchangeError> {
    if reader.read_u8().await? != EXCHANGE {
        return Err(ExchangeError::Protocol);
    }
    let theirs = Epoch(reader.read_u64().await?);
    let mut their_digest = [0_u8; 32];
    reader.read_exact(&mut their_digest).await?;
    // A machine that is not a device takes nothing and gives nothing, and says so with digest zero. One
    // that cannot read its standing says nothing: the dialer reads the closed stream as no answer.
    let Some(pin) = device_pin(home).await? else {
        writer.write_all(&[SAME]).await?;
        writer.write_all(&NONE_YET).await?;
        writer.shutdown().await?;
        return Ok(());
    };
    let (mine, bytes) = held(home, pin);
    let my_digest = digest(&bytes);
    // The fork kept before this exchange: one taken in it came from the dialer.
    let fork = kept_fork(home, pin);
    if theirs == mine && their_digest == my_digest {
        writer.write_all(&[SAME]).await?;
        writer.write_all(&my_digest).await?;
        if my_digest == NONE_YET {
            // Neither side holds an update.
            writer.shutdown().await?;
            touch_synced(home).await;
            return Ok(());
        }
    } else if mine > theirs {
        writer.write_all(&[MINE]).await?;
        write_update(&mut writer, &bytes).await?;
    } else if mine == theirs && !bytes.is_empty() {
        writer.write_all(&[BOTH]).await?;
        write_update(&mut writer, &bytes).await?;
        let update = read_update(&mut reader).await?;
        if let Err(error) = fold_here(home, &update).await {
            tracing::debug!(%error, "refused an update in an exchange");
        }
    } else {
        writer.write_all(&[SEND_YOURS]).await?;
        writer.flush().await?;
        let update = read_update(&mut reader).await?;
        let reply = match fold_here(home, &update).await {
            Ok(Folded::Newer | Folded::Same) => vec![FOLDED],
            Ok(Folded::Fork { floor }) => {
                let mut reply = vec![FORK_RECORDED];
                reply.extend_from_slice(&floor.0.to_be_bytes());
                reply
            }
            Ok(Folded::NotNewer) => vec![REFUSED],
            Err(error) => {
                tracing::debug!(%error, "refused an update in an exchange");
                vec![REFUSED]
            }
        };
        writer.write_all(&reply).await?;
    }
    writer.flush().await?;
    // The updates have moved: forks that fail to pass are logged, and the exchange still ran.
    let forks = async {
        take_fork(home, &mut reader).await?;
        write_update(&mut writer, &fork).await?;
        writer.shutdown().await?;
        Ok::<_, ExchangeError>(())
    };
    if let Err(error) = forks.await {
        tracing::debug!(%error, "could not pass the forks kept in an exchange");
    }
    touch_synced(home).await;
    Ok(())
}

/// The fork of the root `pin` this machine keeps, as its bytes, or empty for none.
fn kept_fork(home: &Home, pin: VerifyKey) -> Vec<u8> {
    read_held(&home.devices_conflict(), pin).map_or_else(Vec::new, |(_, bytes)| bytes)
}

/// Read the fork the other device keeps, and fold it when there is one. A fork that does not fold is
/// dropped: the exchange of the updates held has already run.
async fn take_fork(
    home: &Home,
    reader: &mut (impl AsyncRead + Unpin),
) -> Result<(), ExchangeError> {
    let fork = read_update(reader).await?;
    if !fork.is_empty()
        && let Err(error) = fold_fork_here(home, &fork).await
    {
        tracing::debug!(%error, "dropped a fork passed on in an exchange");
    }
    Ok(())
}

/// Fold an update another device sent, under `home.lock`, taken for the fold alone: never across a read
/// or a write of the exchange.
async fn fold_here(home: &Home, bytes: &[u8]) -> Result<Folded, FoldError> {
    let home_lock = HomeWrite::take(home).await?;
    fold(&home_lock, home, bytes).await
}

/// Fold a fork another device passed on, under `home.lock`, taken for the fold alone.
async fn fold_fork_here(home: &Home, bytes: &[u8]) -> Result<(), FoldError> {
    let home_lock = HomeWrite::take(home).await?;
    fold_fork(&home_lock, home, bytes).await
}

/// Write an update's bytes, after their length.
async fn write_update(
    writer: &mut (impl AsyncWrite + Unpin),
    bytes: &[u8],
) -> Result<(), ExchangeError> {
    let len = u32::try_from(bytes.len()).map_err(|_| ExchangeError::TooLarge)?;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(bytes).await?;
    writer.flush().await?;
    Ok(())
}

/// Read an update's length and bytes, refusing one larger than any update can be before it is read.
async fn read_update(reader: &mut (impl AsyncRead + Unpin)) -> Result<Vec<u8>, ExchangeError> {
    let len = u64::from(reader.read_u32().await?);
    if len > MAX_ROSTER_BLOB {
        return Err(ExchangeError::TooLarge);
    }
    let mut bytes = vec![0_u8; usize::try_from(len).map_err(|_| ExchangeError::TooLarge)?];
    reader.read_exact(&mut bytes).await?;
    Ok(bytes)
}

/// Record that an exchange reached another device, now, owner-only through
/// [`write_private_atomic`](crate::config::write_private_atomic). Best-effort: a failure only makes the next
/// dial exchange again. `invited-by` stays: only a fold that lands a list removes it.
async fn touch_synced(home: &Home) {
    let now = unix_now();
    let home_lock = match HomeWrite::take(home).await {
        Ok(home_lock) => home_lock,
        Err(error) => {
            tracing::debug!(%error, "could not record the sync");
            return;
        }
    };
    let written = crate::config::write_private_atomic(
        &home_lock,
        &home.synced(),
        format!("{now}\n").as_bytes(),
    );
    if let Err(error) = written {
        tracing::debug!(%error, "could not record the sync");
    }
}

/// When an exchange last reached another device, in unix seconds; `None` if never.
pub fn last_synced(home: &Home) -> Option<u64> {
    std::fs::read_to_string(home.synced())
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// How long ago an exchange last reached another device, as a line reads it: "never", or the largest
/// whole unit of minutes, hours or days.
pub fn ago(home: &Home) -> String {
    let Some(then) = last_synced(home) else {
        return "never".to_owned();
    };
    let secs = unix_now().saturating_sub(then);
    let (count, unit) = match secs {
        0..3600 => (secs / 60, "minute"),
        3600..86_400 => (secs / 3600, "hour"),
        _ => (secs / 86_400, "day"),
    };
    let plural = if count == 1 { "" } else { "s" };
    format!("{count} {unit}{plural} ago")
}

/// Something that runs one exchange with a device by its key: a bound node, or a test's stand-in.
pub trait Dial {
    /// Dial `peer`'s `control.sync` and run one exchange as the dialer.
    fn exchange(&self, peer: NodeId) -> impl Future<Output = Result<Answer, ExchangeError>>;

    /// Dial `peer`'s `control.sync` and run one exchange as the dialer, offering `bytes`, the update at
    /// `number` ([`offer`]).
    fn offer(
        &self,
        peer: NodeId,
        number: Epoch,
        bytes: &[u8],
    ) -> impl Future<Output = Result<Answer, ExchangeError>>;
}

/// The [`Dial`] over a bound node: each exchange opens `control.sync` on the device, presenting this
/// machine's standing as it reads now.
pub struct NodeDial<'a, T: Transport, D: Discovery> {
    node: &'a Node<T, D>,
    home: &'a Home,
}

impl<'a, T: Transport, D: Discovery> NodeDial<'a, T, D> {
    /// Exchange over `node`, as the device `home` is.
    pub fn new(node: &'a Node<T, D>, home: &'a Home) -> Self {
        Self { node, home }
    }
}

impl<T: Transport, D: Discovery> NodeDial<'_, T, D> {
    /// Open a stream on `peer`'s `control.sync`, presenting this machine's standing as it reads now.
    async fn open(
        &self,
        peer: NodeId,
    ) -> Result<(impl AsyncRead + Unpin, impl AsyncWrite + Unpin), ExchangeError> {
        let badge = crate::config::load_badge(self.home).await?;
        let session = connector(peer, badge)?.open_service(self.node).await?;
        let (writer, reader) = session.open_bi().await.map_err(|error| match error {
            bifrost::Error::Refused(bifrost::Refusal::NotAdmitted) => ExchangeError::NotAdmitted,
            other => ExchangeError::Dial(eyre::eyre!(other)),
        })?;
        Ok((reader, writer))
    }
}

impl<T: Transport, D: Discovery> Dial for NodeDial<'_, T, D> {
    async fn exchange(&self, peer: NodeId) -> Result<Answer, ExchangeError> {
        let (reader, writer) = self.open(peer).await?;
        exchange(self.home, reader, writer).await
    }

    async fn offer(
        &self,
        peer: NodeId,
        number: Epoch,
        bytes: &[u8],
    ) -> Result<Answer, ExchangeError> {
        let (reader, writer) = self.open(peer).await?;
        offer(self.home, number, bytes, reader, writer).await
    }
}

/// The dial of `peer`'s `control.sync`, presenting `standing`: the one every exchange a node starts makes.
pub fn connector(peer: NodeId, standing: Option<nauthy::Link>) -> eyre::Result<Connector> {
    let service = SYNC_SERVICE
        .parse()
        .map_err(|error| eyre::eyre!("{error}"))?;
    Ok(Connector::to_node(peer, service, standing))
}

/// A device to exchange with: its key, and the name a line gives it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    /// The device's key.
    pub key: NodeId,
    /// `me/<name>`, or the key's short form for a device `me` does not name.
    pub name: String,
}

/// The devices to exchange with, in the order a round asks them: this machine's `me` devices in random
/// order, then `also` (a presented root's live devices) in the order given, then `invited-by`. Never
/// this machine, never a key revoked here or in the update held here, and each key once.
pub async fn devices(
    home: &Home,
    also: impl IntoIterator<Item = (VerifyKey, String)>,
) -> eyre::Result<Vec<Device>> {
    // A key that is not a usable key cannot be dialed, so it is left out.
    let also = also.into_iter().filter_map(|(key, name)| {
        Some(Device {
            key: key.node_id().ok()?,
            name,
        })
    });
    let seed = crate::joining::InvitedBy::read(home).map(|invited| Device {
        key: invited.from,
        name: crate::credential::short(&invited.from),
    });
    let listed = me_devices(home).await?.into_iter().chain(also).chain(seed);
    dialable(home, listed).await
}

/// This machine's `me` devices alone, in the order a round asks them, on the same rules as [`devices`]:
/// the only machines the pick-up route asks.
pub async fn mine(home: &Home) -> eyre::Result<Vec<Device>> {
    let listed = me_devices(home).await?;
    dialable(home, listed).await
}

/// The devices `me` names, in random order.
async fn me_devices(home: &Home) -> eyre::Result<Vec<Device>> {
    let store = ContactsStore::open(home).await?;
    let mut mine: Vec<Device> = store
        .contacts()
        .devices(&Petname::stored(crate::contacts::ME)?)
        .into_iter()
        .flatten()
        .map(|(label, key)| Device {
            key: *key,
            name: format!("me/{label}"),
        })
        .collect();
    mine.shuffle(&mut rand::thread_rng());
    Ok(mine)
}

/// `listed`, in order, without this machine, a key revoked here or in the update held here, or a key
/// already kept.
async fn dialable(
    home: &Home,
    listed: impl IntoIterator<Item = Device>,
) -> eyre::Result<Vec<Device>> {
    let file = keystore::KeyFile::device(home.key());
    let own = file
        .load()?
        .map(|stored| crate::identity::key_of(&file, &stored))
        .transpose()?;
    // The one reader of what this machine refuses, on the gate's rules: a file that cannot be read, is
    // loose, or lost entries fails the list rather than reading as no keys, which would dial a device this
    // machine revoked.
    let revoked_here = crate::revoked::open(home)?;
    let mut revoked: Vec<NodeId> = Vec::new();
    if let Ok(Some(pin)) = device_pin(home).await
        && let Some((doc, _)) = read_held(&home.devices(), pin)
    {
        revoked.extend(doc.revoked_keys().filter_map(|key| key.node_id().ok()));
    }
    let mut out: Vec<Device> = Vec::new();
    for device in listed {
        let skip = Some(device.key) == own
            || revoked.contains(&device.key)
            || device
                .key
                .verify_key()
                .is_ok_and(|key| revoked_here.is_revoked_key(&key))
            || out.iter().any(|kept| kept.key == device.key);
        if !skip {
            out.push(device);
        }
    }
    Ok(out)
}

/// How one device's exchange in a round went.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reply {
    /// The exchange ran, and ended so.
    Answered(Answer),
    /// The device's gate did not admit this machine: the standing it presented was refused.
    NotAdmitted,
    /// The device did not answer in time, or the exchange failed.
    Silent,
}

impl Reply {
    /// The exchange's end, when it ran.
    pub fn answer(self) -> Option<Answer> {
        match self {
            Self::Answered(answer) => Some(answer),
            Self::NotAdmitted | Self::Silent => None,
        }
    }
}

/// When a round stops.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Until {
    /// At the first device that gave this machine a newer update.
    Newer,
    /// Never: every device is asked.
    Every,
}

/// Exchange with `devices` in order, one at a time, each within [`EACH`] and all within `total`. Each
/// device's [`Reply`]; a device left unasked when the round stopped is not listed.
///
/// On [`Until::Every`], a take makes every device asked before it (one found the same, given this
/// machine's list, or taken from) hold an older list than this machine now does, so each is asked again,
/// and its last reply is the one listed.
pub async fn round(
    dial: &impl Dial,
    devices: &[Device],
    until: Until,
    total: Duration,
) -> Vec<(Device, Reply)> {
    let deadline = tokio::time::Instant::now() + total;
    let mut replies: Vec<Option<Reply>> = vec![None; devices.len()];
    let mut queue: VecDeque<usize> = (0..devices.len()).collect();
    while let Some(index) = queue.pop_front() {
        let device = &devices[index];
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        let reply = match tokio::time::timeout(EACH.min(left), dial.exchange(device.key)).await {
            Ok(Ok(answer)) => Reply::Answered(answer),
            Ok(Err(ExchangeError::NotAdmitted)) => {
                tracing::debug!(device = %device.name, "the device did not admit this machine");
                Reply::NotAdmitted
            }
            Ok(Err(error)) => {
                tracing::debug!(device = %device.name, %error, "an exchange failed");
                Reply::Silent
            }
            Err(_) => {
                tracing::debug!(device = %device.name, "an exchange timed out");
                Reply::Silent
            }
        };
        replies[index] = Some(reply);
        if reply == Reply::Answered(Answer::Took) {
            if until == Until::Newer {
                break;
            }
            for (earlier, got) in replies.iter().enumerate() {
                let behind = matches!(
                    got,
                    Some(Reply::Answered(Answer::Same | Answer::Gave | Answer::Took))
                );
                if earlier != index && behind && !queue.contains(&earlier) {
                    queue.push_back(earlier);
                }
            }
        }
    }
    devices
        .iter()
        .zip(replies)
        .filter_map(|(device, reply)| Some((device.clone(), reply?)))
        .collect()
}

/// Whether a round's replies say this machine's own standing was refused: some device's gate did not
/// admit it. Only then is the pick-up route worth trying ([`crate::renewal`]).
pub fn refused(replies: &[(Device, Reply)]) -> bool {
    replies
        .iter()
        .any(|(_, reply)| *reply == Reply::NotAdmitted)
}

/// Whether this machine is a device of a root, one that holds it or not: the only machines that
/// exchange.
pub async fn is_device(home: &Home) -> bool {
    matches!(device_pin(home).await, Ok(Some(_)))
}

/// Whether a dialing verb exchanges on its connection: this machine is a device, and its last exchange
/// with another device is over [`STALE`] old, or never happened.
pub async fn is_stale(home: &Home) -> bool {
    if !is_device(home).await {
        return false;
    }
    let now = unix_now();
    last_synced(home).is_none_or(|then| now.saturating_sub(then) > STALE.as_secs())
}

/// One exchange with `peer` within [`EACH`], as a dialing verb makes it: never printed, and a failure
/// logged at debug.
pub async fn once(dial: &impl Dial, peer: NodeId) -> Option<Answer> {
    match tokio::time::timeout(EACH, dial.exchange(peer)).await {
        Ok(Ok(answer)) => Some(answer),
        Ok(Err(error)) => {
            tracing::debug!(%error, "the stale-list exchange failed");
            None
        }
        Err(_) => {
            tracing::debug!("the stale-list exchange timed out");
            None
        }
    }
}

/// The `me` device `peer` is, when it is one: a dialing verb exchanges only with a device of its own root.
pub async fn is_own_device(home: &Home, peer: NodeId) -> bool {
    devices(home, [])
        .await
        .is_ok_and(|devices| devices.iter().any(|device| device.key == peer))
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

#[cfg(test)]
#[path = "sync_tests.rs"]
mod sync_tests;
