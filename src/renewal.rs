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

use core::cell::RefCell;
use core::future::Future;
use core::time::Duration;
use std::io;
use std::time::SystemTime;

use bifrost::NodeId;
use futures::future::{LocalBoxFuture, Shared};
use futures::stream::FuturesUnordered;
use futures::{FutureExt as _, StreamExt as _};
use nauthy::{Link, Revocations as _, VerifyKey};
use tightbeam::identity::AsVerifyKey as _;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::sync::Notify;
use tokio::time::Instant;

use crate::contacts::{ContactsStore, DeviceLabel};
use crate::home::{Home, HomeWrite};
use crate::peers::Hints;
use crate::roster::{MAX_BADGE, read_held};
use crate::serve::control::Internal;
use crate::serve::control_codec::{OpenLane, OpenRequest};
use crate::serve::{RENEWAL_SERVICE, SYNC_SERVICE};
use crate::standing::Standing;
use crate::streams::{Ask, Opened, StreamSource, Unopened};
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
    if revocations.is_revoked(row.standing.cap()) || revokes_id(&doc, &row.standing) {
        return Err(Miss::IdRevoked);
    }
    match row.standing.cap().valid_until() {
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
    /// The source gave no stream to the other device; why is kept typed, for the log.
    #[error("no stream to the other device opened")]
    Unopened(Unopened),
}

/// Something that asks one device's pick-up route by its key: a bound node, or a test's stand-in.
pub trait Fetch {
    /// Ask `peer`'s `control.renewal` for this machine's standing: `Some` on a hit, `None` on a miss.
    fn fetch(&self, peer: NodeId) -> impl Future<Output = Result<Option<Link>, FetchError>>;
}

/// The [`Fetch`] over a stream source: `control.renewal` on Main with no slip, a proven-only route, so
/// it presents nothing and reads no badge: a dead or unreadable badge cannot delay a pick-up.
pub struct SourceFetch<'a, S: StreamSource> {
    source: &'a S,
}

impl<'a, S: StreamSource> SourceFetch<'a, S> {
    /// Ask each device's pick-up route through `source`.
    pub fn new(source: &'a S) -> Self {
        Self { source }
    }
}

impl<S: StreamSource> Fetch for SourceFetch<'_, S> {
    async fn fetch(&self, peer: NodeId) -> Result<Option<Link>, FetchError> {
        let ask = Ask {
            peer,
            hints: Hints::NONE,
            service: RENEWAL_SERVICE
                .parse()
                .map_err(|error| eyre::eyre!("{error}"))?,
            lane: OpenLane::Main,
            slip: None,
        };
        // The route refuses a key it does not know, and every key while its slots are full: to the dialer
        // that is the same miss as the one byte.
        let Opened {
            mut write, read, ..
        } = match self.source.open(&ask).await {
            Ok(opened) => opened,
            Err(Unopened::Refused(_)) => return Ok(None),
            Err(other) => return Err(FetchError::Unopened(other)),
        };
        // End the empty upload before reading, so the peer reads a clean end, never a reset that can stop
        // its answer from completing. The route answers without reading, so a failed End is no failure.
        if let Err(error) = write.shutdown().await {
            tracing::debug!(%error, "the pick-up's upload did not end cleanly");
        }
        read_answer(read).await
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

/// Whether this home's standing needs the route: it is a device's, and it has passed its date, or its id
/// is revoked here or by the update held here. On any other home, on one whose files cannot be read, and
/// on one whose own key a list held here revokes, it does not: that home can take no renewal
/// ([`take_renewal`](crate::joining::take_renewal)), so waiting on one would only stall it.
pub async fn is_due(home: &Home, now: SystemTime) -> bool {
    let (pin, until) = match Standing::read(home).await {
        Ok(Standing::Device { pin, until } | Standing::HoldsRoot { pin, until }) => (pin, until),
        Ok(Standing::Unpinned | Standing::InterruptedMint { .. }) | Err(_) => return false,
    };
    let Ok(pin) = pin.verify_key() else {
        return false;
    };
    // Before the date: a lapsed home whose key is revoked would otherwise stall every verb on a renewal.
    if crate::root::own_key_revoked(home, pin).unwrap_or(true) {
        return false;
    }
    if until <= now {
        return true;
    }
    let Ok(Some(badge)) = crate::config::load_badge(home).await else {
        return false;
    };
    crate::revoked::open(home).is_ok_and(|revoked| revoked.is_revoked(badge.cap()))
        || held_update_revokes_id(home, pin, &badge)
}

/// Whether the update held here, under `pin`, revokes `standing`'s id. A fold copies an update's revoked
/// ids into the revocations file, but `devices` is the record, so it is read as [`standing_for`] reads it.
pub(crate) fn held_update_revokes_id(home: &Home, pin: VerifyKey, standing: &Link) -> bool {
    read_held(&home.devices(), pin).is_some_and(|(doc, _)| revokes_id(&doc, standing))
}

/// Whether `doc` revokes `standing`'s id.
fn revokes_id(doc: &crate::roster::RosterDoc, standing: &Link) -> bool {
    standing
        .cap()
        .root_revocation_id()
        .is_some_and(|id| doc.revoked().iter().any(|revoked| revoked.id == id))
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
    /// A standing this machine took from `from`, ending at `until`.
    async fn here(home: &Home, from: String, until: SystemTime) -> Self {
        Self {
            from,
            name: own_name(home).await,
            until,
        }
    }

    /// The day the standing it took ends, as a line prints it.
    pub fn ends(&self) -> crate::root::Date {
        crate::root::Date(
            self.until
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_or(0, |since| since.as_secs()),
        )
    }
}

/// Ask your devices under `me` for this machine's standing, once each within [`EACH`], in the order an
/// exchange asks them, and take the first that the same-root write takes. Never a machine outside `me`.
/// `home.lock` is waited for as long as another change holds it, and no timer ever covers
/// [`take_renewal`](crate::joining::take_renewal): once the lock is held, the read and the one atomic write
/// run to their end.
pub async fn pick_up(home: &Home, fetch: &impl Fetch) -> eyre::Result<Option<Renewed>> {
    for device in crate::sync::mine(home).await? {
        let Some(fetched) = ask(fetch, &device, Instant::now() + EACH).await else {
            continue;
        };
        let home_lock = HomeWrite::take(home).await?;
        let taken = crate::joining::take_renewal(&home_lock, home, &fetched).await?;
        drop(home_lock);
        if let Some(until) = taken {
            return Ok(Some(Renewed::here(home, device.name, until).await));
        }
        tracing::debug!(device = %device.name, "a fetched standing was not taken");
    }
    Ok(None)
}

/// Ask `device` until `deadline`: the standing it handed over, or `None` for every other end, each traced.
async fn ask(fetch: &impl Fetch, device: &Device, deadline: Instant) -> Option<Link> {
    match tokio::time::timeout_at(deadline, fetch.fetch(device.key)).await {
        Ok(Ok(Some(standing))) => Some(standing),
        Ok(Ok(None)) => {
            tracing::debug!(device = %device.name, "no renewal there");
            None
        }
        Ok(Err(error)) => {
            tracing::debug!(device = %device.name, ?error, "the pick-up failed");
            None
        }
        Err(_) => {
            tracing::debug!(device = %device.name, "the pick-up timed out");
            None
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
/// standing needs a renewal: try the pick-up route. A failure to run is a miss like any other.
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

/// How long the device asks of a renewal before an `Open` may take: every device is asked at once, and
/// every ask ends by then.
const OPEN_ASKS: Duration = Duration::from_secs(6);

/// How long a renewal before an `Open` waits for `home.lock` at most, each time, within its bound.
const OPEN_LOCK: Duration = Duration::from_secs(2);

/// The bound on a renewal before an `Open`, from its start to its end, which the wait for an `Open`'s
/// reply counts. The write after the lock is not timed: it is one atomic file write.
pub const OPEN_RENEWAL: Duration = Duration::from_secs(8);

const _: () = assert!(OPEN_ASKS.as_millis() + OPEN_LOCK.as_millis() == OPEN_RENEWAL.as_millis());
// Every device is asked at once, each with a whole `EACH`, so on a stalled Main session its open's own
// deadline fires and evicts before the ask is cut.
const _: () = assert!(EACH.as_millis() <= OPEN_ASKS.as_millis());

/// How long after a miss an `Open` does not ask again. The hourly round keeps asking meanwhile.
pub const OPEN_BACK_OFF: Duration = Duration::from_secs(5 * 60);

/// How long after it was fetched a standing kept while another change held `home.lock` may still be
/// written.
const OPEN_KEEP: Duration = Duration::from_secs(5 * 60);

/// The renewal a resident runs before an `Open` that presents this home's standing, when that standing is
/// due: one flight at a time, shared by every `Open` that arrives while it runs, bounded by
/// [`OPEN_RENEWAL`], and not tried again for [`OPEN_BACK_OFF`] after it misses. Either way the `Open` then
/// goes on with whatever standing the home holds.
///
/// Borrowed by the resident for its run, which polls [`drive`](Self::drive) beside its control
/// socket: a flight runs to its end and its end counts even when every `Open` waiting on it has left,
/// so `Open`s that are cancelled cannot start flights at will. Structured: no task is spawned, and
/// dropping it drops any flight.
pub struct OpenRenewal<'a, F: Fetch> {
    home: &'a Home,
    fetch: &'a F,
    // The resident's opens and its run interleave on one task, so a `RefCell` suffices; no borrow crosses
    // an await.
    state: RefCell<Asking<'a>>,
    // Wakes `drive` when an `Open` starts a flight. A start while `drive` is not waiting leaves a permit,
    // so no flight goes undriven.
    started: Notify,
}

/// Where the renewal before an `Open` stands.
enum Asking<'a> {
    /// Nothing in flight, no recent miss, and nothing kept.
    Idle,
    /// A flight runs; an `Open` that arrives now waits on it rather than asking again.
    Flying(Flight<'a>),
    /// The last flight missed at this instant.
    Missed(Instant),
    /// The last flight fetched a standing and could not take `home.lock` in time. The next flight tries to
    /// write it before asking anyone. Dropped when that flight starts; one older than [`OPEN_KEEP`] is
    /// dropped unused.
    Kept(Kept),
}

/// One shared renewal, polled by the run and by every `Open` waiting on it, so it never depends on the
/// `Open` that started it.
type Flight<'a> = Shared<LocalBoxFuture<'a, Landed>>;

/// A standing one of your devices handed over that could not be written yet. It is written only through
/// the same-root write, which re-reads the home under `home.lock`.
#[derive(Debug, Clone)]
struct Kept {
    standing: Link,
    /// The device it came from, `me/<name>`.
    from: String,
    /// When it was fetched.
    at: Instant,
}

/// How a flight ended.
#[derive(Debug, Clone)]
enum Landed {
    /// The standing was not due, so nothing was asked.
    NotDue,
    /// This machine took its renewal.
    Took(Renewed),
    /// A miss: nothing was taken, through no answer, no renewal, a refusal, or a read or write error.
    Missed,
    /// A standing was fetched and `home.lock` was not taken before the flight's end. Not a miss: the lock
    /// is held by a command on this machine, which says nothing about any device.
    Kept(Kept),
}

impl Landed {
    /// What an `Open` waiting on the flight reads. A kept standing is not yet a renewal.
    fn pick_up(&self) -> PickUp {
        match self {
            Self::NotDue => PickUp::Skipped,
            Self::Took(renewed) => PickUp::Took(renewed.clone()),
            Self::Missed | Self::Kept(_) => PickUp::Missed,
        }
    }

    /// Where the renewal stands after this end. Only a miss starts the back-off.
    fn next<'a>(self) -> Asking<'a> {
        match self {
            Self::NotDue | Self::Took(_) => Asking::Idle,
            Self::Missed => Asking::Missed(Instant::now()),
            Self::Kept(kept) => Asking::Kept(kept),
        }
    }
}

impl<'a, F: Fetch> OpenRenewal<'a, F> {
    /// The renewal step over `home`, asking your devices through `fetch`.
    pub fn new(home: &'a Home, fetch: &'a F) -> Self {
        Self {
            home,
            fetch,
            state: RefCell::new(Asking::Idle),
            started: Notify::new(),
        }
    }

    /// Before `open` is dialed: renew this home's standing when the `Open` presents it and it is due.
    ///
    /// An `Open` with a slip presents the slip, a proven-only route presents nothing, and an exchange
    /// presents its standing as it is, its refusal being what sends its caller to the pick-up: none of
    /// them renews first.
    pub async fn before(&self, open: &OpenRequest) -> PickUp {
        let service = open.service().as_str();
        if open.slip().is_some() || service == SYNC_SERVICE || Internal::is_proven(service) {
            return PickUp::Skipped;
        }
        let flight = {
            let mut state = self.state.borrow_mut();
            match &*state {
                Asking::Flying(flight) => flight.clone(),
                Asking::Missed(at) if at.elapsed() < OPEN_BACK_OFF => return PickUp::Skipped,
                Asking::Missed(_) | Asking::Idle | Asking::Kept(_) => {
                    let kept = match core::mem::replace(&mut *state, Asking::Idle) {
                        Asking::Kept(kept) if kept.at.elapsed() < OPEN_KEEP => Some(kept),
                        _ => None,
                    };
                    let flight = Self::fly(self.home, self.fetch, kept)
                        .boxed_local()
                        .shared();
                    *state = Asking::Flying(flight.clone());
                    self.started.notify_one();
                    flight
                }
            }
        };
        let landed = flight.clone().await;
        self.land(&flight, &landed);
        landed.pick_up()
    }

    /// Drive every flight an `Open` starts to its end, for as long as the run serves its control socket,
    /// beside it ([`Opens::drive`](crate::serve::Opens::drive)).
    pub async fn drive(&self) -> core::convert::Infallible {
        loop {
            let flying = match &*self.state.borrow() {
                Asking::Flying(flight) => Some(flight.clone()),
                Asking::Idle | Asking::Missed(_) | Asking::Kept(_) => None,
            };
            match flying {
                Some(flight) => {
                    let landed = flight.clone().await;
                    self.land(&flight, &landed);
                }
                None => self.started.notified().await,
            }
        }
    }

    /// Settle the state on `flight`'s end. The run and every waiter call this; only the first, while
    /// `flight` is still the current one, moves it.
    fn land(&self, flight: &Flight<'a>, landed: &Landed) {
        let mut state = self.state.borrow_mut();
        if matches!(&*state, Asking::Flying(current) if current.ptr_eq(flight)) {
            *state = landed.clone().next();
        }
    }

    /// One flight. When the standing is due: the kept standing first, then every device at once, the
    /// first standing taken winning. It ends [`OPEN_RENEWAL`] after it starts: every ask by
    /// [`OPEN_ASKS`], and each wait for `home.lock` within [`OPEN_LOCK`] and the time left.
    async fn fly(home: &'a Home, fetch: &'a F, kept: Option<Kept>) -> Landed {
        let start = Instant::now();
        let (asks_end, end) = (start + OPEN_ASKS, start + OPEN_RENEWAL);
        if !is_due(home, SystemTime::now()).await {
            return Landed::NotDue;
        }
        if let Some(kept) = kept {
            match take_by(home, &kept.standing, end).await {
                Taken::Took(until) => {
                    return Landed::Took(Renewed::here(home, kept.from, until).await);
                }
                Taken::Refused => {
                    tracing::debug!(device = %kept.from, "a kept standing was not taken")
                }
                Taken::LockHeld => return Landed::Kept(kept),
                Taken::Failed => return Landed::Missed,
            }
        }
        let devices = match crate::sync::mine(home).await {
            Ok(devices) => devices,
            Err(error) => {
                tracing::debug!(%error, "the pick-up could not list your devices");
                return Landed::Missed;
            }
        };
        let deadline = asks_end.min(Instant::now() + EACH);
        let mut asks: FuturesUnordered<_> = devices
            .into_iter()
            .map(|device| async move {
                let fetched = ask(fetch, &device, deadline).await;
                (device, fetched)
            })
            .collect();
        // Answers are taken as they come. While one is being written the other asks are not polled, but
        // their deadline still runs, so none outlives it.
        while let Some((device, fetched)) = asks.next().await {
            let Some(fetched) = fetched else {
                continue;
            };
            let at = Instant::now();
            match take_by(home, &fetched, end).await {
                Taken::Took(until) => {
                    return Landed::Took(Renewed::here(home, device.name, until).await);
                }
                Taken::Refused => {
                    tracing::debug!(device = %device.name, "a fetched standing was not taken");
                    after_refusal().await;
                }
                Taken::LockHeld => {
                    return Landed::Kept(Kept {
                        standing: fetched,
                        from: device.name,
                        at,
                    });
                }
                Taken::Failed => return Landed::Missed,
            }
        }
        Landed::Missed
    }
}

/// After a refused write, before the next answer is read: a test widens it, so an answer already in is
/// written only after the asks have ended. Per thread, so only the test that sets it is slowed.
async fn after_refusal() {
    #[cfg(test)]
    if let Some(pause) = AFTER_REFUSAL.get() {
        tokio::time::sleep(pause).await;
    }
}

#[cfg(test)]
thread_local! {
    static AFTER_REFUSAL: core::cell::Cell<Option<Duration>> = const { core::cell::Cell::new(None) };
}

/// How one try at writing a fetched standing ended.
enum Taken {
    /// Written; the standing ends then.
    Took(SystemTime),
    /// The same-root write refused it.
    Refused,
    /// `home.lock` was not taken in time.
    LockHeld,
    /// The lock or the home could not be read or written.
    Failed,
}

/// Write `standing` through the same-root write, waiting for `home.lock` within [`OPEN_LOCK`] and never
/// past `end`. Taking the lock is a try and a sleep, so a timeout ends it between tries, never with the
/// lock held.
async fn take_by(home: &Home, standing: &Link, end: Instant) -> Taken {
    let wait = end.min(Instant::now() + OPEN_LOCK);
    let home_lock = match tokio::time::timeout_at(wait, HomeWrite::take(home)).await {
        Ok(Ok(home_lock)) => home_lock,
        Ok(Err(error)) => {
            tracing::debug!(%error, "home.lock could not be taken");
            return Taken::Failed;
        }
        Err(_) => {
            tracing::debug!("home.lock was held past the renewal's bound");
            return Taken::LockHeld;
        }
    };
    match crate::joining::take_renewal(&home_lock, home, standing).await {
        Ok(Some(until)) => Taken::Took(until),
        Ok(None) => Taken::Refused,
        Err(error) => {
            tracing::debug!(%error, "the fetched standing could not be written");
            Taken::Failed
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
pub(crate) mod renewal_tests;
