//! The pick-up route: a device whose standing has ended, or was revoked here, takes its renewal from one
//! of your devices, with nothing pasted.
//!
//! Every update carries every live device's newest standing ([`crate::roster`]), and every `serve` holds
//! the update, so any of your devices can hand a device its own. One request per stream of
//! `control.renewal`, a proven-only route: the dialer presents nothing and sends nothing, and the server
//! reads only the key the transport proved:
//!
//! ```text
//! server -> 0x01, length (u16), standing (bare link text)    that key's newest standing
//!           0x00                                             anything else, whatever the cause
//! ```
//!
//! then closes. The server signs nothing and sends no other row. The dialer takes what it fetched only
//! through the same-root write a join makes ([`crate::joining::take_renewal`]), so nothing fetched can
//! pin a root or change which key this machine is.

use core::future::Future;
use core::time::Duration;
use std::io;
use std::time::SystemTime;

use bifrost::{Discovery, Node, NodeId, Session as _, Transport};
use nauthy::{Link, Revocations as _, VerifyKey};
use tightbeam::tunnel::Connector;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

use crate::contacts::{ContactsStore, DeviceLabel, ME, Petname};
use crate::home::Home;
use crate::roster::{MAX_BADGE, read_held};
use crate::serve::RENEWAL_SERVICE;
use crate::standing::Standing;
use crate::sync::{Device, Reply};

/// The answer that carries a standing.
const HIT: u8 = 0x01;

/// The one answer for every miss.
const MISS: u8 = 0x00;

/// How long one device may take to answer.
pub const EACH: Duration = crate::sync::EACH;

/// Why the route missed, for this machine's trace only: the peer reads the same one byte for every cause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Miss {
    /// This machine is not a device of a root, or its pin is not a key.
    NotADevice,
    /// The revocations here could not be read, so nothing is handed out.
    Unreadable,
    /// The peer's key is in `revoked`.
    KeyRevoked,
    /// The update held here lists no device for the key, or none verifies under the pin.
    NoRow,
    /// The update held here revokes the key.
    RowRevoked,
    /// The row's standing id is revoked.
    IdRevoked,
    /// The row's standing has ended.
    Ended,
}

/// Answer one stream of `control.renewal` for `peer`, the key the transport proved: its standing, or the
/// one miss. Never reads from the peer.
pub async fn answer(
    home: &Home,
    peer: VerifyKey,
    mut writer: impl AsyncWrite + Unpin,
) -> io::Result<()> {
    let reply = match standing_for(home, peer, SystemTime::now()).await {
        Ok(standing) => hit(&standing),
        Err(miss) => {
            tracing::debug!(?miss, "the pick-up route missed");
            vec![MISS]
        }
    };
    writer.write_all(&reply).await?;
    writer.shutdown().await
}

/// The hit's bytes: the status byte, the length, the standing. A standing longer than any update carries
/// is a miss, though no verified update holds one.
fn hit(standing: &Link) -> Vec<u8> {
    let text = standing.as_str().as_bytes();
    let Ok(length) = u16::try_from(text.len()) else {
        return vec![MISS];
    };
    let mut out = Vec::with_capacity(3 + text.len());
    out.push(HIT);
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(text);
    out
}

/// `peer`'s newest standing, checked in this order: the key is not revoked here, its row in the update
/// held here is not revoked, the row's standing id is not revoked, and the standing outlives `now`. The
/// transport proved the key before the stream reached here.
async fn standing_for(home: &Home, peer: VerifyKey, now: SystemTime) -> Result<Link, Miss> {
    let pin = match Standing::read(home).await {
        Ok(Standing::Device { pin, .. } | Standing::HoldsRoot { pin, .. }) => pin,
        Ok(Standing::Unpinned | Standing::InterruptedMint { .. }) | Err(_) => {
            return Err(Miss::NotADevice);
        }
    };
    let pin = crate::standing::pin_key(home, pin).map_err(|_| Miss::NotADevice)?;
    let revocations = crate::revoked::open(home).map_err(|_| Miss::Unreadable)?;
    if revocations.is_revoked_peer(&peer) {
        return Err(Miss::KeyRevoked);
    }
    let (doc, _) = read_held(&home.devices(), pin).ok_or(Miss::NoRow)?;
    let row = doc
        .members()
        .iter()
        .find(|member| member.node == peer)
        .ok_or(Miss::NoRow)?;
    if doc.is_revoked_key(&peer) {
        return Err(Miss::RowRevoked);
    }
    let cap = row.standing.cap();
    let id_revoked = revocations.is_revoked(cap)
        || cap
            .root_revocation_id()
            .is_some_and(|id| doc.revoked().iter().any(|revoked| revoked.id == id));
    if id_revoked {
        return Err(Miss::IdRevoked);
    }
    match cap.expiry() {
        Ok(Some(ends)) if ends > now => Ok(row.standing.clone()),
        _ => Err(Miss::Ended),
    }
}

/// Why one device's pick-up route gave no answer this machine could read.
#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    /// The stream failed.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// The other side said something the route does not.
    #[error("the other device answered out of turn")]
    Protocol,
    /// The other device could not be reached.
    #[error(transparent)]
    Dial(#[from] eyre::Report),
}

/// Something that asks one device's pick-up route by its key: a bound node, or a test's stand-in.
pub trait Fetch {
    /// Ask `peer`'s `control.renewal` for this machine's standing: `Some` on a hit, `None` on a miss.
    fn fetch(&self, peer: NodeId) -> impl Future<Output = Result<Option<Link>, FetchError>>;
}

/// The [`Fetch`] over a bound node: each ask opens `control.renewal` on the device, presenting nothing.
pub struct NodeFetch<'a, T: Transport, D: Discovery> {
    node: &'a Node<T, D>,
}

impl<'a, T: Transport, D: Discovery> NodeFetch<'a, T, D> {
    /// Ask over `node`, under the key it is bound to.
    pub fn new(node: &'a Node<T, D>) -> Self {
        Self { node }
    }
}

impl<T: Transport, D: Discovery> Fetch for NodeFetch<'_, T, D> {
    async fn fetch(&self, peer: NodeId) -> Result<Option<Link>, FetchError> {
        let service = RENEWAL_SERVICE
            .parse()
            .map_err(|error| eyre::eyre!("{error}"))?;
        let session = Connector::to_node(peer, service, None)
            .open_service(self.node)
            .await?;
        // The route refuses a key it does not know, and every key while its slots are full: to the dialer
        // that is the same miss as the one byte.
        let (_writer, reader) = match session.open_bi().await {
            Ok(stream) => stream,
            Err(bifrost::Error::Refused(_)) => return Ok(None),
            Err(other) => return Err(eyre::eyre!(other).into()),
        };
        read_answer(reader).await
    }
}

/// Read the route's one answer: the standing on a hit, `None` on a miss.
pub async fn read_answer(mut reader: impl AsyncRead + Unpin) -> Result<Option<Link>, FetchError> {
    match reader.read_u8().await? {
        MISS => Ok(None),
        HIT => {
            let length = usize::from(reader.read_u16().await?);
            if length > MAX_BADGE {
                return Err(FetchError::Protocol);
            }
            let mut bytes = vec![0_u8; length];
            reader.read_exact(&mut bytes).await?;
            let text = String::from_utf8(bytes).map_err(|_| FetchError::Protocol)?;
            text.parse::<Link>()
                .map(Some)
                .map_err(|_| FetchError::Protocol)
        }
        _ => Err(FetchError::Protocol),
    }
}

/// Whether this home's standing needs the route: it is a device's, and it has passed its date or its id
/// is revoked here. On any other home, and on one whose files cannot be read, it does not.
pub async fn is_due(home: &Home, now: SystemTime) -> bool {
    let until = match Standing::read(home).await {
        Ok(Standing::Device { until, .. } | Standing::HoldsRoot { until, .. }) => until,
        Ok(Standing::Unpinned | Standing::InterruptedMint { .. }) | Err(_) => return false,
    };
    if until <= now {
        return true;
    }
    let Ok(Some(badge)) = crate::config::load_badge(home).await else {
        return false;
    };
    crate::revoked::open(home).is_ok_and(|revoked| revoked.is_revoked(badge.cap()))
}

/// A standing this machine took from one of your devices.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Renewed {
    /// The device it came from, `me/<name>`.
    pub from: String,
    /// This machine, `me/<name>`, or its key's short form when `me` does not name it.
    pub name: String,
    /// When the standing it took ends.
    pub until: SystemTime,
}

impl Renewed {
    /// The day the standing it took ends, as a line prints it.
    pub fn ends(&self) -> crate::root::Date {
        crate::root::Date(
            self.until
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_or(0, |since| since.as_secs()),
        )
    }
}

/// Ask your devices under `me` for this machine's standing, once each, in the order an exchange asks
/// them, and take the first that the same-root write takes. Never a machine outside `me`.
pub async fn pick_up(home: &Home, fetch: &impl Fetch) -> eyre::Result<Option<Renewed>> {
    for device in crate::sync::mine(home).await? {
        let fetched = match tokio::time::timeout(EACH, fetch.fetch(device.key)).await {
            Ok(Ok(Some(standing))) => standing,
            Ok(Ok(None)) => {
                tracing::debug!(device = %device.name, "no renewal there");
                continue;
            }
            Ok(Err(error)) => {
                tracing::debug!(device = %device.name, %error, "the pick-up failed");
                continue;
            }
            Err(_) => {
                tracing::debug!(device = %device.name, "the pick-up timed out");
                continue;
            }
        };
        let home_lock = crate::home::HomeWrite::take(home).await?;
        let taken = crate::joining::take_renewal(&home_lock, home, &fetched).await?;
        drop(home_lock);
        if let Some(until) = taken {
            return Ok(Some(Renewed {
                from: device.name,
                name: own_name(home).await,
                until,
            }));
        }
        tracing::debug!(device = %device.name, "a fetched standing was not taken");
    }
    Ok(None)
}

/// What the pick-up route did after a round of exchanges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PickUp {
    /// Not tried: no device refused this machine's standing, or it needs no renewal.
    Skipped,
    /// Tried, and this machine took its renewal.
    Took(Renewed),
    /// Tried, and none of your devices had a renewal it took.
    Missed,
}

/// After a round whose `replies` show a device refused this machine's standing, and only when that
/// standing needs a renewal: try the pick-up route.
pub async fn after_round(home: &Home, fetch: &impl Fetch, replies: &[(Device, Reply)]) -> PickUp {
    if !crate::sync::refused(replies) || !is_due(home, SystemTime::now()).await {
        return PickUp::Skipped;
    }
    match pick_up(home, fetch).await {
        Ok(Some(renewed)) => PickUp::Took(renewed),
        Ok(None) => PickUp::Missed,
        Err(error) => {
            tracing::debug!(%error, "the pick-up could not run");
            PickUp::Missed
        }
    }
}

/// This machine's name among your devices, `me/<name>`; the key's short form when `me` does not name it.
pub async fn own_name(home: &Home) -> String {
    if let Some(label) = own_label(home).await {
        return format!("me/{label}");
    }
    let file = keystore::KeyFile::new(home.key());
    file.load()
        .ok()
        .flatten()
        .and_then(|stored| crate::identity::key_of(&file, &stored).ok())
        .map_or_else(
            || "this machine".to_owned(),
            |key| crate::credential::short(&key),
        )
}

/// The name `me` gives this machine, when it gives one: only the name a verified list of your devices
/// holds, never the unsigned name an invite carried, so a command built on it never names another device.
pub async fn own_label(home: &Home) -> Option<DeviceLabel> {
    let file = keystore::KeyFile::new(home.key());
    let own = crate::identity::key_of(&file, &file.load().ok().flatten()?).ok()?;
    let store = ContactsStore::open(home).await.ok()?;
    let me = Petname::stored(ME).ok()?;
    store
        .contacts()
        .devices(&me)
        .and_then(|mut devices| devices.find(|(_, key)| **key == own))
        .map(|(label, _)| label.clone())
}

#[cfg(test)]
#[path = "renewal_tests.rs"]
mod renewal_tests;
