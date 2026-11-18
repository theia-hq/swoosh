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
//!
//! A machine asks after a round a device refused it in, before a verb dials with a due standing, and,
//! through a running `serve`, before an `Open` that presents a due standing ([`OpenRenewal`]), there
//! within a fixed bound.

use core::cell::{Cell, RefCell};
use core::future::Future;
use core::time::Duration;
use std::io;
use std::rc::Rc;
use std::time::SystemTime;

use bifrost::{Discovery, NodeId, Transport};
use futures::FutureExt as _;
use futures::future::{LocalBoxFuture, Shared};
use nauthy::{Link, Revocations as _, VerifyKey};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::time::Instant;

use crate::contacts::{ContactsStore, DeviceLabel};
use crate::home::{Home, HomeWrite};
use crate::peers::{Lane, OpenError, Presents};
use crate::roster::{MAX_BADGE, read_held};
use crate::serve::control_codec::OpenRequest;
use crate::serve::{PROVEN_ROUTES, RENEWAL_SERVICE, SYNC_SERVICE};
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
    let standing = standing_for(home, peer, SystemTime::now())
        .await
        .inspect_err(|miss| tracing::debug!(?miss, "the pick-up route missed"))
        .ok();
    writer.write_all(&reply(standing.as_ref())).await?;
    writer.shutdown().await
}

/// One answer's bytes, the format both proven-only routes speak (this one and `lookup.root`): on a hit the
/// status byte, the length, the standing; else the one miss byte. A standing longer than any update
/// carries is a miss, though no verified update holds one.
pub(crate) fn reply(standing: Option<&Link>) -> Vec<u8> {
    let Some(standing) = standing else {
        return vec![MISS];
    };
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
/// held here is not revoked, the row's standing id is not revoked, and its effective expiry bound
/// has not passed. The transport proved the key before the stream reached here.
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
    match cap.valid_until() {
        Ok(Some(ends)) if ends >= now => Ok(row.standing.clone()),
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

/// The [`Fetch`] over the run's credential-free Main sessions. No home is borrowed or badge read:
/// a dead or unreadable badge cannot delay a pick-up or shorten its session's lease.
pub struct NodeFetch<'p, 'n, T: Transport, D: Discovery> {
    peers: &'p crate::peers::Peers<'n, T, D>,
}

impl<'p, 'n, T: Transport, D: Discovery> NodeFetch<'p, 'n, T, D> {
    /// Borrow only the run's sessions; every ask presents neither credential slot.
    pub fn new(peers: &'p crate::peers::Peers<'n, T, D>) -> Self {
        Self { peers }
    }
}

impl<T: Transport, D: Discovery> Fetch for NodeFetch<'_, '_, T, D> {
    async fn fetch(&self, peer: NodeId) -> Result<Option<Link>, FetchError> {
        let service = RENEWAL_SERVICE
            .parse()
            .map_err(|error| eyre::eyre!("{error}"))?;
        // The route refuses a key it does not know, and every key while its slots are full: to the dialer
        // that is the same miss as the one byte. No badge lookup belongs on this path, even for a key.
        let (_writer, reader) = match self
            .peers
            .open(peer, service, Lane::Main, Presents::Standing(None))
            .await
        {
            Ok(stream) => stream,
            Err(OpenError::Open(bifrost::Error::Refused(_))) => return Ok(None),
            Err(other) => return Err(eyre::eyre!(other).into()),
        };
        read_answer(reader).await
    }
}

/// Read the route's one answer: the standing on a hit, `None` on a miss. Both proven-only routes answer
/// in this format ([`reply`]).
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
    pick_up_within(home, fetch, Bound::Each).await
}

/// The body of [`pick_up`], under `bound`. No timer ever covers [`take_renewal`](crate::joining::take_renewal):
/// once `home.lock` is held, the read and the one atomic write run to their end.
async fn pick_up_within(
    home: &Home,
    fetch: &impl Fetch,
    bound: Bound,
) -> eyre::Result<Option<Renewed>> {
    for device in crate::sync::mine(home).await? {
        let Some(ask) = bound.ask() else {
            tracing::debug!(device = %device.name, "no time left to ask");
            break;
        };
        let fetched = match tokio::time::timeout(ask, fetch.fetch(device.key)).await {
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
        let home_lock = bound.lock(home).await?;
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

/// What bounds one pick-up's waits.
#[derive(Debug, Clone, Copy)]
enum Bound {
    /// A verb's or a round's own: each device within [`EACH`], and `home.lock` waited for as long as
    /// another change holds it.
    Each,
    /// Before an `Open`: every ask ends by `asks`, and `home.lock` is taken within [`OPEN_LOCK`].
    Open {
        /// When the device asks, all together, must end.
        asks: Instant,
    },
}

impl Bound {
    /// An `Open`'s bound, its asks starting now.
    fn open() -> Self {
        Self::Open {
            asks: Instant::now() + OPEN_ASKS,
        }
    }

    /// How long the next device may take, or `None` when the asks' share has run out.
    fn ask(self) -> Option<Duration> {
        match self {
            Self::Each => Some(EACH),
            Self::Open { asks } => {
                let left = asks.saturating_duration_since(Instant::now());
                (!left.is_zero()).then(|| EACH.min(left))
            }
        }
    }

    /// Take `home.lock`. Taking it is a try and a sleep, so a timeout ends it between tries, never with
    /// the lock held.
    async fn lock(self, home: &Home) -> eyre::Result<HomeWrite> {
        match self {
            Self::Each => Ok(HomeWrite::take(home).await?),
            Self::Open { .. } => tokio::time::timeout(OPEN_LOCK, HomeWrite::take(home))
                .await
                .map_err(|_| eyre::eyre!("home.lock was held past {OPEN_LOCK:?}"))?
                .map_err(Into::into),
        }
    }
}

/// What the pick-up route did after a round of exchanges, or before an `Open`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PickUp {
    /// Not tried: no device refused this machine's standing, it needs no renewal, the `Open` does not
    /// present it, or an `Open`'s last try missed under [`OPEN_BACK_OFF`] ago.
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
    try_pick_up(home, fetch, Bound::Each).await
}

/// A pick-up under `bound`, whose failure to run is a miss like any other.
async fn try_pick_up(home: &Home, fetch: &impl Fetch, bound: Bound) -> PickUp {
    match pick_up_within(home, fetch, bound).await {
        Ok(Some(renewed)) => PickUp::Took(renewed),
        Ok(None) => PickUp::Missed,
        Err(error) => {
            tracing::debug!(%error, "the pick-up could not run");
            PickUp::Missed
        }
    }
}

/// How long the device asks of a renewal before an `Open` may take, all together.
const OPEN_ASKS: Duration = Duration::from_secs(6);

/// How long a renewal before an `Open` waits for `home.lock`.
const OPEN_LOCK: Duration = Duration::from_secs(2);

/// The bound on a renewal before an `Open`, which the wait for an `Open`'s reply counts. The write after
/// the lock is not timed: it is one atomic file write.
pub const OPEN_RENEWAL: Duration = Duration::from_secs(8);

const _: () = assert!(OPEN_ASKS.as_millis() + OPEN_LOCK.as_millis() == OPEN_RENEWAL.as_millis());
// The first device always gets a whole ask, so on a stalled Main session its open's own deadline fires
// and evicts before the ask is cut. A second or later device gets only what is left of the asks, which
// may be less than the Main open deadline, so its ask can be cut first and cannot evict a stalled session.
const _: () = assert!(EACH.as_millis() <= OPEN_ASKS.as_millis());

/// How long after a miss an `Open` does not ask again. The hourly round keeps asking meanwhile.
pub const OPEN_BACK_OFF: Duration = Duration::from_secs(5 * 60);

/// The renewal a resident runs before an `Open` that presents this home's standing, when that standing is
/// due: one flight at a time, shared by every `Open` that arrives while it runs, bounded by
/// [`OPEN_RENEWAL`], and not tried again for [`OPEN_BACK_OFF`] after it misses. Either way the `Open` then
/// goes on with whatever standing the home holds.
///
/// Borrowed by the resident for its run. Structured: no task is spawned, and dropping it drops any flight.
pub struct OpenRenewal<'a, F: Fetch> {
    home: &'a Home,
    fetch: &'a F,
    // The resident's opens interleave on one task, so a `RefCell` suffices; no borrow crosses an await.
    state: RefCell<Asking<'a>>,
}

/// Where the renewal before an `Open` stands.
enum Asking<'a> {
    /// Nothing in flight, and no recent miss.
    Idle,
    /// A flight runs; an `Open` that arrives now waits on it rather than asking again.
    Flying(Rc<Flight<'a>>),
    /// The last flight missed at this instant.
    Missed(Instant),
}

/// One shared renewal. Polled by whichever waiter runs, so it never depends on the `Open` that started it.
struct Flight<'a> {
    future: Shared<LocalBoxFuture<'a, PickUp>>,
    waiters: Cell<u16>,
}

impl<'a, F: Fetch> OpenRenewal<'a, F> {
    /// The renewal step over `home`, asking your devices through `fetch`.
    pub fn new(home: &'a Home, fetch: &'a F) -> Self {
        Self {
            home,
            fetch,
            state: RefCell::new(Asking::Idle),
        }
    }

    /// Before `open` is dialed: renew this home's standing when the `Open` presents it and it is due.
    ///
    /// An `Open` with a slip presents the slip, a proven-only route presents nothing, and an exchange
    /// presents its standing as it is, its refusal being what sends its caller to the pick-up: none of
    /// them renews first.
    pub async fn before(&self, open: &OpenRequest) -> PickUp {
        let service = open.service().as_str();
        if open.slip().is_some() || service == SYNC_SERVICE || PROVEN_ROUTES.contains(&service) {
            return PickUp::Skipped;
        }
        let flight = {
            let mut state = self.state.borrow_mut();
            match &*state {
                Asking::Flying(flight) => Rc::clone(flight),
                Asking::Missed(at) if at.elapsed() < OPEN_BACK_OFF => return PickUp::Skipped,
                Asking::Missed(_) | Asking::Idle => {
                    let flight = Rc::new(Flight {
                        future: Self::fly(self.home, self.fetch).boxed_local().shared(),
                        waiters: Cell::new(0),
                    });
                    *state = Asking::Flying(Rc::clone(&flight));
                    flight
                }
            }
        };
        flight.waiters.set(flight.waiters.get() + 1);
        let waiting = Waiting {
            state: &self.state,
            flight: Rc::clone(&flight),
        };
        let done = flight.future.clone().await;
        let mut state = self.state.borrow_mut();
        if matches!(&*state, Asking::Flying(current) if Rc::ptr_eq(current, &flight)) {
            *state = match done {
                PickUp::Missed => Asking::Missed(Instant::now()),
                PickUp::Took(_) | PickUp::Skipped => Asking::Idle,
            };
        }
        drop(state);
        drop(waiting);
        done
    }

    /// One flight: when the standing is due, a pick-up under an `Open`'s bound.
    async fn fly(home: &'a Home, fetch: &'a F) -> PickUp {
        if !is_due(home, SystemTime::now()).await {
            return PickUp::Skipped;
        }
        try_pick_up(home, fetch, Bound::open()).await
    }
}

/// One `Open` waiting on a flight. The last to leave before it lands clears it, so the next `Open` starts
/// afresh, with a whole bound, rather than resuming a flight whose deadlines have passed.
struct Waiting<'s, 'a> {
    state: &'s RefCell<Asking<'a>>,
    flight: Rc<Flight<'a>>,
}

impl Drop for Waiting<'_, '_> {
    fn drop(&mut self) {
        let remaining = self.flight.waiters.get() - 1;
        self.flight.waiters.set(remaining);
        if remaining != 0 {
            return;
        }
        let mut state = self.state.borrow_mut();
        if matches!(&*state, Asking::Flying(current) if Rc::ptr_eq(current, &self.flight)) {
            *state = Asking::Idle;
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
    store
        .contacts()
        .mine()
        .find(|(_, key)| **key == own)
        .map(|(label, _)| label.clone())
}

#[cfg(test)]
#[path = "renewal_tests.rs"]
mod renewal_tests;
