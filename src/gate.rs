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
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

use bifrost::NodeId;
use nauthy::{
    Cap, DenylistError, DisabledRoots, DisabledRootsError, FileDenylist, FileStamp, Gate, Latch,
    PinSource, Revocations, STAT_DEBOUNCE, VerifyKey,
};
use tightbeam::identity::{AsNodeId as _, AsVerifyKey as _};
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
    /// The revoked device keys could not be read, or lost keys they once held.
    #[error(transparent)]
    RevokedKeys(#[from] RevokedKeysError),
}

/// Why `<home>/revoked_keys` may not be loaded as it reads.
#[derive(Debug, thiserror::Error)]
pub enum RevokedKeysError {
    /// The file, or its `.written` witness, exists but could not be read.
    #[error("read {}", path.display())]
    Io {
        /// The file that could not be read.
        path: PathBuf,
        /// Why.
        #[source]
        source: std::io::Error,
    },
    /// The file is larger than [`MAX_REVOKED_KEYS_LEN`].
    #[error("{} is larger than {MAX_REVOKED_KEYS_LEN} bytes", path.display())]
    TooLarge {
        /// The file.
        path: PathBuf,
    },
    /// The file holds fewer keys than its `.written` witness says a write left there (an absent file holds
    /// none). No write shrinks it, so keys were lost to a deletion, a truncation, or a crash, and loading
    /// it would admit them again.
    #[error(
        "{} holds {found} revoked keys but held {expected}: restore it, re-revoke what is missing, or remove {}.written to accept the loss",
        path.display(),
        path.display()
    )]
    Lost {
        /// The keys file.
        path: PathBuf,
        /// The count the witness records.
        expected: u64,
        /// The distinct keys the file holds now.
        found: u64,
    },
}

/// The most bytes `<home>/revoked_keys` may hold: room for thousands of keys, and a bound on what one
/// admission reads.
pub const MAX_REVOKED_KEYS_LEN: u64 = 1 << 20;

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
/// Both are read in full at load, where a file that cannot be read or holds fewer entries than its
/// `.written` witness refuses the load. After that both reload when their [`FileStamp`] changes, and both
/// keep the last set they read when their file is missing or cannot be read, since a deleted revocation
/// must never un-revoke. The keys file only ever grows, so a read adds to the set and never removes from it.
pub struct KeyedDenylist {
    links: FileDenylist,
    keys: RevokedKeys,
}

impl KeyedDenylist {
    /// Load both files under `home`, each on the same witness rules: a missing file holds nothing only
    /// while its `.written` witness is absent or zero.
    pub async fn load(home: &Home) -> Result<Self, GateError> {
        Ok(Self {
            links: FileDenylist::load(home.revoked()).await?,
            keys: RevokedKeys::load(home.revoked_keys(), &home.revoked_keys_written())?,
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
    /// Read the keys at `path` now, and check them against the witness at `written`.
    // `core::io::ErrorKind` is still unstable, so the error kinds read from `std`.
    #[allow(clippy::std_instead_of_core)]
    fn load(path: PathBuf, written: &Path) -> Result<Self, RevokedKeysError> {
        let (keys, stamp) = match read_keys(&path) {
            Ok(Some(read)) => read,
            Ok(None) => (HashSet::new(), None),
            Err(error) if error.kind() == std::io::ErrorKind::FileTooLarge => {
                return Err(RevokedKeysError::TooLarge { path });
            }
            Err(source) => return Err(RevokedKeysError::Io { path, source }),
        };
        let found = u64::try_from(keys.len()).unwrap_or(u64::MAX);
        match read_witness(written) {
            Ok(Some(expected)) if found < expected => {
                return Err(RevokedKeysError::Lost {
                    path,
                    expected,
                    found,
                });
            }
            Ok(_) => {}
            Err(source) => {
                return Err(RevokedKeysError::Io {
                    path: written.to_path_buf(),
                    source,
                });
            }
        }
        Ok(Self {
            path,
            state: Mutex::new(KeysState {
                keys,
                stamp,
                last_stat: Some(Instant::now()),
            }),
        })
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
        if FileStamp::unchanged(state.stamp, FileStamp::of(&meta)) {
            return;
        }
        match read_keys(&self.path) {
            Ok(Some((keys, stamp))) => {
                state.keys.extend(keys);
                state.stamp = stamp;
            }
            Ok(None) => {}
            Err(error) => tracing::warn!(
                path = %self.path.display(),
                %error,
                "keeping the revoked keys already read"
            ),
        }
    }
}

/// Add `keys` to `<home>/revoked_keys`, and raise its `.written` witness to the count it now holds.
///
/// Under the exclusive flock on `<home>/revoked_keys.lock`, it re-reads the file, writes the union to a
/// sibling and renames it over, so two writers each keep what the other added and no write shrinks the
/// file. A file that cannot be read is never replaced: it may hold keys this write cannot see.
pub fn add_revoked_keys(home: &Home, keys: &[VerifyKey]) -> Result<(), RevokedKeysError> {
    use std::io::Write as _;
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    if keys.is_empty() {
        return Ok(());
    }
    let path = home.revoked_keys();
    let io = |path: &Path| {
        let path = path.to_path_buf();
        move |source| RevokedKeysError::Io { path, source }
    };
    let lock_path = home.revoked_keys_lock();
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&lock_path)
        .map_err(io(&lock_path))?;
    // SAFETY: `lock` owns a valid fd for the whole call, and `flock` only attaches an advisory lock to it.
    // Without `LOCK_NB` it waits for another writer, whose section is as short and synchronous as this one.
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(io(&lock_path)(std::io::Error::last_os_error()));
    }
    let mut held = match read_keys(&path) {
        Ok(Some((held, _))) => held,
        Ok(None) => HashSet::new(),
        Err(source) => return Err(RevokedKeysError::Io { path, source }),
    };
    let before = held.len();
    held.extend(keys.iter().copied());
    if held.len() == before {
        return Ok(());
    }
    let mut lines: Vec<String> = held.iter().map(|key| key.node_id().to_string()).collect();
    lines.sort();
    let body = lines.join("\n") + "\n";
    let write = |target: &Path, bytes: &[u8]| -> std::io::Result<()> {
        let mut temp = target.as_os_str().to_owned();
        temp.push(".new");
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&temp, target)
    };
    write(&path, body.as_bytes()).map_err(io(&path))?;
    let witness = home.revoked_keys_written();
    write(&witness, format!("{}\n", lines.len()).as_bytes()).map_err(io(&witness))
}

/// Read the keys file at `path` and its stamp from one open handle, or `None` when there is no file. More
/// than [`MAX_REVOKED_KEYS_LEN`] bytes is `FileTooLarge`, found before the excess is buffered. A line that
/// is not a key is skipped and logged; it counts toward nothing.
// `core::io::ErrorKind` is still unstable, so the error kinds read from `std`.
#[allow(clippy::std_instead_of_core)]
fn read_keys(path: &Path) -> std::io::Result<Option<(HashSet<VerifyKey>, Option<FileStamp>)>> {
    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let mut text = String::new();
    (&mut file)
        .take(MAX_REVOKED_KEYS_LEN + 1)
        .read_to_string(&mut text)?;
    if u64::try_from(text.len()).unwrap_or(u64::MAX) > MAX_REVOKED_KEYS_LEN {
        return Err(std::io::ErrorKind::FileTooLarge.into());
    }
    let stamp = file.metadata().ok().and_then(|meta| FileStamp::of(&meta));
    let mut keys = HashSet::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match line.parse::<NodeId>() {
            Ok(key) => {
                keys.insert(key.verify_key());
            }
            Err(error) => tracing::warn!(
                path = %path.display(),
                line = index + 1,
                %error,
                "skipping a line that is not a key"
            ),
        }
    }
    Ok(Some((keys, stamp)))
}

/// The count in the `.written` witness at `path`, or `None` when there is none. A witness that is not a
/// count is an error: guessing it would either refuse a sound file forever or accept a lost one.
// `core::io::ErrorKind` is still unstable, so the error kinds read from `std`.
#[allow(clippy::std_instead_of_core)]
fn read_witness(path: &Path) -> std::io::Result<Option<u64>> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    text.trim().parse().map(Some).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "the witness is not a count",
        )
    })
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
