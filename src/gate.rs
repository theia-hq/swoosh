//! What `serve`'s gate reads: the live pin ([`FilePin`]), the revocations ([`KeyedDenylist`] behind the
//! latch of disabled roots), and the live cut over both ([`AnchorCut`]).
//!
//! [`anchored`] builds the one gate `serve` runs in every standing: nauthy's anchored gate over the pin as
//! it stands at each admission, this machine's own key, the revocations, and the ledger of links this
//! machine signed ([`IssuedLedger`]). The pin and the latch are each one shared instance, read by the gate
//! at admission and by the cut on every sweep, so the two never disagree about a file they each read at a
//! different moment.
//!
//! Nothing here treats this machine's own key as a root. The own key admits only the links this machine
//! recorded signing, and a pin that names the own key is no pin: that rule lives in nauthy's gate alone.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

use bifrost::NodeId;
use nauthy::{
    Cap, DenylistError, DisabledRoots, DisabledRootsError, FileDenylist, FileStamp, Gate, Latch,
    PinSource, Revocations, STAT_DEBOUNCE, VerifyKey,
};
use tightbeam::identity::AsVerifyKey as _;
use tightbeam::tunnel::{AdmittedChains, LiveCuts};

use crate::grants::IssuedLedger;
use crate::home::Home;

/// The revocations `serve` honors: the disabled roots latched over this machine's [`KeyedDenylist`].
pub type Revoked = Latch<KeyedDenylist>;

/// Build `serve`'s gate over `home`, for a machine whose own key is `own`, and the live cut that must be
/// wired beside it (`.with_live_cuts(cut)`).
///
/// The same in every standing: a machine with no pin admits no member, a pin to a root disabled here is
/// no pin, and a link this machine signed is admitted whatever the pin, while its row is in the ledger.
pub async fn anchored(home: &Home, own: NodeId) -> Result<(Gate, AnchorCut), GateError> {
    let latch = Arc::new(Latch::new(
        DisabledRoots::load(home.disabled_roots()).await?,
        KeyedDenylist::load(home).await?,
    ));
    let pin = Arc::new(FilePin::open(home, Arc::clone(&latch)));
    let own = own.verify_key();
    let gate = Gate::anchored(
        Arc::clone(&pin),
        own,
        Arc::clone(&latch),
        IssuedLedger::open(home),
    );
    Ok((gate, AnchorCut { pin, own, latch }))
}

/// Why `serve`'s gate could not be built.
#[derive(Debug, thiserror::Error)]
pub enum GateError {
    /// The disabled roots could not be read, or lost keys they once held.
    #[error(transparent)]
    Disabled(#[from] DisabledRootsError),
    /// The revoked links could not be read, or lost ids they once held.
    #[error(transparent)]
    Denylist(#[from] DenylistError),
}

/// The pin as `serve` reads it: `<home>/signet`, afresh on every admission.
///
/// It re-stats the file at most once per [`STAT_DEBOUNCE`] and re-reads it when its [`FileStamp`]
/// changed, so a pin written while `serve` runs is trusted at the next admission with no restart.
///
/// Its failures read as no pin, the inverse of the denylist's: a missing file, a failed stat or read, a
/// body that is not exactly one key, or a key the latch disabled all read as `None`, and the path is
/// logged once per change. It never keeps a pin from an earlier read. The latch is read through the same
/// instance the gate holds.
pub struct FilePin {
    path: PathBuf,
    latch: Arc<Revoked>,
    state: Mutex<PinState>,
}

/// What a [`FilePin`] read last.
struct PinState {
    /// What the last look at the file found, before the latch is asked.
    read: Reading,
    /// The stamp of the file the key came from, `None` before a read or after a failed one.
    stamp: Option<FileStamp>,
    /// When the file was last statted, to debounce the next stat.
    last_stat: Option<Instant>,
    /// What the pin read as when it was last logged, so a change is logged once.
    logged: Option<Reading>,
}

/// What the pin reads as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reading {
    /// No pin file.
    Missing,
    /// The file could not be statted or read.
    Unreadable,
    /// The file is not exactly one key.
    Malformed,
    /// The file names a root disabled here.
    Latched,
    /// The file names this root.
    Pinned(VerifyKey),
}

impl FilePin {
    /// The pin at `<home>/signet`, checked against `latch`. Reads nothing until it is first asked.
    pub fn open(home: &Home, latch: Arc<Revoked>) -> Self {
        Self {
            path: home.signet(),
            latch,
            state: Mutex::new(PinState {
                read: Reading::Missing,
                stamp: None,
                last_stat: None,
                logged: None,
            }),
        }
    }

    /// Re-read the file when its stamp changed, at most once per [`STAT_DEBOUNCE`], and say what the pin
    /// reads as now. Every failure replaces the key, so no earlier read survives it.
    // `core::io::ErrorKind` is still unstable, so the NotFound check reads from `std`.
    #[allow(clippy::std_instead_of_core)]
    fn refresh(&self, state: &mut PinState) -> Reading {
        let due = state
            .last_stat
            .is_none_or(|last| last.elapsed() >= STAT_DEBOUNCE);
        if due {
            state.last_stat = Some(Instant::now());
            match std::fs::metadata(&self.path) {
                Err(error) => {
                    state.stamp = None;
                    state.read = if error.kind() == std::io::ErrorKind::NotFound {
                        Reading::Missing
                    } else {
                        Reading::Unreadable
                    };
                }
                Ok(meta) => {
                    let stamp = FileStamp::of(&meta);
                    if !FileStamp::unchanged(state.stamp, stamp) {
                        match std::fs::read_to_string(&self.path) {
                            Err(_) => {
                                state.stamp = None;
                                state.read = Reading::Unreadable;
                            }
                            Ok(text) => {
                                state.stamp = stamp;
                                state.read =
                                    one_key(&text).map_or(Reading::Malformed, Reading::Pinned);
                            }
                        }
                    }
                }
            }
        }
        match state.read {
            Reading::Pinned(key) if self.latch.disabled().is_disabled(key) => Reading::Latched,
            reading => reading,
        }
    }

    /// Log `reading` when it differs from the last one logged.
    fn log(&self, state: &mut PinState, reading: Reading) {
        if state.logged == Some(reading) {
            return;
        }
        state.logged = Some(reading);
        let path = self.path.display();
        match reading {
            Reading::Missing => tracing::warn!(path = %path, "no pin: no member is admitted"),
            Reading::Unreadable => {
                tracing::warn!(path = %path, "the pin cannot be read: no member is admitted");
            }
            Reading::Malformed => {
                tracing::warn!(path = %path, "the pin is not one key: no member is admitted");
            }
            Reading::Latched => {
                tracing::warn!(path = %path, "the pin names a revoked root: no member is admitted");
            }
            Reading::Pinned(key) => tracing::info!(path = %path, root = %key, "pinned"),
        }
    }
}

/// The key in a pin file's `text`: exactly one key and nothing else, or `None`.
fn one_key(text: &str) -> Option<VerifyKey> {
    let body = text.trim();
    if body.lines().count() != 1 {
        return None;
    }
    body.parse::<NodeId>().ok().map(|key| key.verify_key())
}

impl PinSource for FilePin {
    fn current(&self) -> Option<VerifyKey> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let reading = self.refresh(&mut state);
        self.log(&mut state, reading);
        match reading {
            Reading::Pinned(key) => Some(key),
            Reading::Missing | Reading::Unreadable | Reading::Malformed | Reading::Latched => None,
        }
    }
}

/// This machine's revocations: the revoked links in `<home>/revoked`, and the revoked device keys in
/// `<home>/revoked_keys`.
///
/// Both reload when their [`FileStamp`] changes, and both keep the last set they read when their file is
/// missing or cannot be read, since a deleted revocation must never un-revoke. The keys file only ever
/// grows, so a read adds to the set and never removes from it.
pub struct KeyedDenylist {
    links: FileDenylist,
    keys: RevokedKeys,
}

impl KeyedDenylist {
    /// Load both files under `home`. A missing `revoked_keys` holds no keys.
    pub async fn load(home: &Home) -> Result<Self, DenylistError> {
        Ok(Self {
            links: FileDenylist::load(home.revoked()).await?,
            keys: RevokedKeys::open(home.revoked_keys()),
        })
    }
}

impl Revocations for KeyedDenylist {
    fn is_revoked(&self, cap: &Cap) -> bool {
        self.links.is_revoked(cap)
    }

    fn is_revoked_peer(&self, peer: &VerifyKey) -> bool {
        self.keys.contains(peer)
    }
}

/// The cut of a session admitted on a revoked link is the link denylist's. The latch this sits behind
/// asks [`is_revoked_peer`](Revocations::is_revoked_peer) for the session's peer, and keeps the default
/// [`trusts`](LiveCuts::trusts): a latch knows no pin.
impl LiveCuts for KeyedDenylist {
    fn cuts(&self, chains: &AdmittedChains) -> bool {
        self.links.cuts(chains)
    }
}

/// The revoked device keys, one per line in their file, read live.
struct RevokedKeys {
    path: PathBuf,
    state: Mutex<KeysState>,
}

/// What a [`RevokedKeys`] has read.
struct KeysState {
    /// Every key any read found.
    keys: HashSet<VerifyKey>,
    /// The stamp of the file last read.
    stamp: Option<FileStamp>,
    /// When the file was last statted, to debounce the next stat.
    last_stat: Option<Instant>,
}

impl RevokedKeys {
    /// The keys at `path`, read at the first check.
    fn open(path: PathBuf) -> Self {
        Self {
            path,
            state: Mutex::new(KeysState {
                keys: HashSet::new(),
                stamp: None,
                last_stat: None,
            }),
        }
    }

    /// Whether `peer` is revoked, re-reading the file first when it changed.
    fn contains(&self, peer: &VerifyKey) -> bool {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        self.refresh(&mut state);
        state.keys.contains(peer)
    }

    /// Union the file into the held set when its stamp changed, at most once per [`STAT_DEBOUNCE`]. Every
    /// failure keeps the set.
    fn refresh(&self, state: &mut KeysState) {
        if state
            .last_stat
            .is_some_and(|last| last.elapsed() < STAT_DEBOUNCE)
        {
            return;
        }
        state.last_stat = Some(Instant::now());
        let Ok(meta) = std::fs::metadata(&self.path) else {
            return;
        };
        let stamp = FileStamp::of(&meta);
        if FileStamp::unchanged(state.stamp, stamp) {
            return;
        }
        let Ok(text) = std::fs::read_to_string(&self.path) else {
            return;
        };
        for (index, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            match line.parse::<NodeId>() {
                Ok(key) => {
                    state.keys.insert(key.verify_key());
                }
                Err(error) => tracing::warn!(
                    path = %self.path.display(),
                    line = index + 1,
                    %error,
                    "skipping a line that is not a key"
                ),
            }
        }
        state.stamp = stamp;
    }
}

/// The live cut `serve` wires beside its gate: it ends a session whose link was revoked or whose root was
/// disabled, a session anchored at a root this machine no longer trusts, and a session whose peer's key
/// was revoked.
///
/// A session is anchored at the root its first link verified under: the pin, or this machine's own key
/// for a link this machine signed. The own key is always trusted, so a link session outlives a change of
/// pin, and a session under the old pin ends within a sweep of the change.
pub struct AnchorCut {
    pin: Arc<FilePin>,
    own: VerifyKey,
    latch: Arc<Revoked>,
}

impl LiveCuts for AnchorCut {
    fn cuts(&self, chains: &AdmittedChains) -> bool {
        self.latch.cuts(chains)
    }

    fn trusts(&self, anchor: &VerifyKey) -> bool {
        Some(*anchor) == self.pin.current() || *anchor == self.own
    }

    fn revoked_peer(&self, peer: &VerifyKey) -> bool {
        self.latch.is_revoked_peer(peer)
    }
}

#[cfg(test)]
#[path = "gate_tests.rs"]
mod gate_tests;
