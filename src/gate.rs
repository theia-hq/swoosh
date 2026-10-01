//! What `serve`'s gate reads: the live pin ([`FilePin`]), this machine's revocations (`<home>/revoked`,
//! through [`crate::revoked`]), and the live cut over both ([`AnchorCut`]).
//!
//! [`anchored`] builds the one gate `serve` runs in every standing: nauthy's anchored gate over the pin as
//! it stands at each admission, this machine's own key, the revocations, and the ledger of links this
//! machine signed ([`IssuedLedger`]). The pin and the revocations are each one shared instance, read by the gate
//! at admission and by the cut on every sweep, so the two never disagree about a file they each read at a
//! different moment.
//!
//! Nothing here treats this machine's own key as a root. The own key admits only the links this machine
//! recorded signing, and a pin that names the own key is no pin: that rule lives in nauthy's gate alone.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

use bifrost::NodeId;
use nauthy::{Denylist, FileStamp, Gate, PinSource, STAT_DEBOUNCE, VerifyKey};
use tightbeam::identity::AsVerifyKey as _;
use tightbeam::tunnel::{AdmittedChains, LiveCuts};

use crate::escape::EscapedPath;
use crate::grants::IssuedLedger;
use crate::home::{Home, Loose, LooseFile, loose_in, read_trust_file};
use crate::revoked::RevokedError;

/// Build `serve`'s gate over `home`, for a machine whose own key is `own`, and the live cut that must be
/// wired beside it (`.with_live_cuts(cut)`).
///
/// The same in every standing: a machine with no pin admits no member, a pin to a root revoked here is
/// no pin, and a link this machine signed is admitted whatever the pin, while its row is in the ledger.
pub async fn anchored(home: &Home, own: NodeId) -> Result<(Gate, AnchorCut), GateError> {
    anchored_admitting(home, own, None).await
}

/// [`anchored`], admitting the devices of `admit` for this run in place of the pin when it is given: a
/// `serve --admit` on a machine that trusts no root. Nothing is written.
pub async fn anchored_admitting(
    home: &Home,
    own: NodeId,
    admit: Option<VerifyKey>,
) -> Result<(Gate, AnchorCut), GateError> {
    let revoked = Arc::new(crate::revoked::open(home)?);
    let mut file_pin = FilePin::open(home, Arc::clone(&revoked));
    file_pin.admit = admit;
    let pin = Arc::new(file_pin);
    let own = own.verify_key()?;
    let gate = Gate::anchored(
        Arc::clone(&pin),
        own,
        Arc::clone(&revoked),
        IssuedLedger::open(home),
    );
    Ok((gate, AnchorCut { pin, own, revoked }))
}

/// Why `serve`'s gate could not be built.
#[derive(Debug, thiserror::Error)]
pub enum GateError {
    /// The revocations could not be read, or lost entries they once held.
    #[error(transparent)]
    Revoked(#[from] RevokedError),
    /// This machine's own key is not a usable key.
    #[error("this machine's key is not a usable key: {0}")]
    OwnKey(#[from] nauthy::KeyError),
}

/// The pin as `serve` reads it: `<home>/root.pub`, afresh on every admission.
///
/// It re-stats the file at most once per [`STAT_DEBOUNCE`] and re-reads it when its [`FileStamp`]
/// changed, so a pin written while `serve` runs is trusted at the next admission with no restart.
///
/// Its failures read as no pin, the inverse of the denylist's: a missing file, a failed stat or read, a
/// file another user owns or others can write (checked on the handle each read comes from), a body that
/// is not exactly one key, or a key revoked here all read as `None`, and the path is logged once per
/// change. It never keeps a pin from an earlier read. The revocations are read through the same instance
/// the gate holds.
pub struct FilePin {
    path: PathBuf,
    revoked: Arc<Denylist>,
    state: Mutex<PinState>,
    /// The root a `serve --admit` admits for its run, read in place of the file.
    admit: Option<VerifyKey>,
}

/// What a [`FilePin`] read last.
struct PinState {
    /// What the last look at the file found, before the revocations are asked.
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
    /// Another user owns the file, or group or other can write it.
    Loose(Loose),
    /// The file is not exactly one key.
    Malformed,
    /// The file names a root revoked here.
    Revoked,
    /// The file names this root.
    Pinned(VerifyKey),
}

impl FilePin {
    /// The pin at `<home>/root.pub`, checked against `revoked`. Reads nothing until it is first asked.
    pub fn open(home: &Home, revoked: Arc<Denylist>) -> Self {
        Self {
            path: home.root_pub(),
            revoked,
            admit: None,
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
                        match read_trust_file(&self.path) {
                            Err(error) => {
                                state.stamp = None;
                                state.read =
                                    loose_in(&error).map_or(Reading::Unreadable, Reading::Loose);
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
            Reading::Pinned(key) if self.revoked.is_revoked_key(&key) => Reading::Revoked,
            reading => reading,
        }
    }

    /// Log `reading` when it differs from the last one logged.
    fn log(&self, state: &mut PinState, reading: Reading) {
        if state.logged == Some(reading) {
            return;
        }
        state.logged = Some(reading);
        // The home path is escaped here, at the call site: the subscriber passes CR, LF and bidi raw, so a
        // home whose directory names hold them would forge or rewrite a line of the serve log.
        let path = EscapedPath(&self.path);
        match reading {
            Reading::Missing => tracing::warn!(path = %path, "no pin: no member is admitted"),
            Reading::Unreadable => {
                tracing::warn!(path = %path, "the pin cannot be read: no member is admitted");
            }
            Reading::Loose(why) => {
                let error = LooseFile {
                    path: self.path.clone(),
                    why,
                };
                tracing::warn!(path = %path, %error, "the pin is refused: no member is admitted");
            }
            Reading::Malformed => {
                tracing::warn!(path = %path, "the pin is not one key: no member is admitted");
            }
            Reading::Revoked => {
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
    body.parse::<VerifyKey>().ok()
}

impl PinSource for FilePin {
    fn current(&self) -> Option<VerifyKey> {
        if let Some(admit) = self.admit {
            return (!self.revoked.is_revoked_key(&admit)).then_some(admit);
        }
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let reading = self.refresh(&mut state);
        self.log(&mut state, reading);
        match reading {
            Reading::Pinned(key) => Some(key),
            Reading::Missing
            | Reading::Unreadable
            | Reading::Loose(_)
            | Reading::Malformed
            | Reading::Revoked => None,
        }
    }
}

/// The live cut `serve` wires beside its gate: it ends a session whose link was revoked or whose root key
/// was revoked, a session anchored at a root this machine no longer trusts, and a session whose peer's key
/// was revoked.
///
/// A session is anchored at the root its first link verified under: the pin, or this machine's own key
/// for a link this machine signed. The own key is always trusted, so a link session outlives a change of
/// pin, and a session under the old pin ends within a sweep of the change.
pub struct AnchorCut {
    pin: Arc<FilePin>,
    own: VerifyKey,
    revoked: Arc<Denylist>,
}

impl LiveCuts for AnchorCut {
    fn cuts(&self, chains: &AdmittedChains) -> bool {
        self.revoked.cuts(chains)
    }

    fn trusts(&self, anchor: &VerifyKey) -> bool {
        Some(*anchor) == self.pin.current() || *anchor == self.own
    }

    fn revoked_peer(&self, peer: &VerifyKey) -> bool {
        self.revoked.is_revoked_key(peer)
    }
}

#[cfg(test)]
#[path = "gate_tests.rs"]
mod gate_tests;
