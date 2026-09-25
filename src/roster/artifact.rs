//! The signed update in the node home: `<home>/roster`, written where a root act cuts it and served on
//! demand.
//!
//! Signing needs the root, and a long-lived `serve` must never hold it, so the cut cannot happen per
//! request. It happens where the change happens instead: the root act that cuts writes this file, and
//! `serve` only ever READS it.
//!
//! It also makes the roster eligible for the refresh shape this family already uses twice
//! ([`nauthy::FileDenylist`] and [`tightbeam::enabled::FileDisabledList`]): read on demand, with a
//! debounced stat, no watcher anywhere. [`Artifact`] is the third instance of that same oracle, not a
//! third refresh mechanism, so a member added while `serve` is running is picked up on the next pull with
//! no restart.

use core::time::Duration;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Instant, SystemTime};

/// The stat debounce, mirroring `nauthy::FileDenylist` and `tightbeam::FileDisabledList` so all three
/// oracles behave identically. A pull is far rarer than an admit, so this is not a hot-path saving; it is
/// the house shape, and the one constant a reader already knows.
const STAT_DEBOUNCE: Duration = Duration::from_millis(100);

/// The signet-signed roster blob at `<home>/roster`, re-read when it changes underneath a running node.
///
/// Hold one per served node. [`bytes`](Self::bytes) hands the handler the current blob; a membership edit
/// in another process rewrites the file and the next read picks it up, so the fleet a puller sees is the
/// fleet as of its pull, not as of the serve that started last week.
pub struct Artifact {
    path: PathBuf,
    state: Mutex<State>,
}

/// The loaded blob, the `(mtime, len)` stamp of the file it was read at, and when the file was last
/// stat'd. The length pairs with mtime so a change within one coarse mtime tick is still seen.
struct State {
    blob: Arc<Vec<u8>>,
    stamp: Option<(SystemTime, u64)>,
    last_stat: Option<Instant>,
}

impl Artifact {
    /// Open the oracle over `path`. An ABSENT file is an empty artifact, not an error or a `None`.
    ///
    /// This is what lets every `serve` bind the update route before this home holds any roster, and
    /// start serving one the moment it is written, with no restart. An absent backing file that appears
    /// later is picked up by the ordinary refresh, exactly as it is for both sibling oracles.
    ///
    /// The bytes and the `(mtime, len)` stamp come from ONE opened handle, so a file replaced during this
    /// load cannot stamp the old bytes as current and make every later refresh skip a real re-cut. That is
    /// the same race both sibling oracles close, and for the same reason.
    pub async fn open(path: PathBuf) -> Result<Self, ArtifactError> {
        let (blob, stamp) = match tokio::fs::File::open(&path).await {
            Ok(mut file) => {
                let stamp = stamp_of(&file.metadata().await.map_err(ArtifactError::Read)?);
                let mut blob = Vec::new();
                tokio::io::AsyncReadExt::read_to_end(&mut file, &mut blob)
                    .await
                    .map_err(ArtifactError::Read)?;
                (blob, stamp)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => (Vec::new(), None),
            Err(error) => return Err(ArtifactError::Read(error)),
        };
        Ok(Self {
            path,
            state: Mutex::new(State {
                blob: Arc::new(blob),
                stamp,
                last_stat: None,
            }),
        })
    }

    /// The file backing this artifact.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The current signed blob, refreshed from disk first if the file changed since the last read. EMPTY
    /// when the signet has not cut one yet; a caller that would hand those bytes to a puller refuses
    /// instead, because zero bytes decode as a bad signature and read to the operator as a forgery.
    ///
    /// Returns the bytes by [`Arc`] so the handler writes them without holding the lock across an await.
    pub fn bytes(&self) -> Arc<Vec<u8>> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        self.refresh(&mut state);
        Arc::clone(&state.blob)
    }

    /// Reload the blob in place if the backing file's `(mtime, len)` differs from what was last read.
    ///
    /// Keeps the last-known blob on EVERY uncertainty: a stat error, a read error, or the file
    /// disappearing. Serving the previous signed snapshot is always safe (a puller's floor refuses
    /// anything not newer than what it holds), while dropping to empty would turn a botched cleanup into a
    /// fleet-wide "you have no members".
    // `core::io::ErrorKind` is still unstable, so any NotFound handling reads from `std`.
    #[allow(clippy::std_instead_of_core)]
    fn refresh(&self, state: &mut State) {
        // Debounce: skip the stat entirely if we checked within the last STAT_DEBOUNCE. The first read
        // after construction (`last_stat` is None) always stats, so a freshly-loaded artifact sees the
        // current file at once.
        if let Some(last) = state.last_stat
            && last.elapsed() < STAT_DEBOUNCE
        {
            return;
        }
        state.last_stat = Some(Instant::now());
        let current = match std::fs::metadata(&self.path) {
            Ok(meta) => stamp_of(&meta),
            Err(_) => return,
        };
        if current == state.stamp {
            return;
        }
        let Ok(blob) = std::fs::read(&self.path) else {
            return;
        };
        state.blob = Arc::new(blob);
        state.stamp = current;
    }

    /// Write `blob`, a signed update, to `path`, replacing the previous one.
    ///
    /// Written to a sibling temp and renamed over the target, so a `serve` reading concurrently sees the
    /// old blob or the new one, never a torn one; the artifact is public (it is handed to every member) so
    /// it takes no private mode.
    pub async fn write(path: &Path, blob: &[u8]) -> Result<(), ArtifactError> {
        if let Some(parent) = path.parent() {
            crate::config::create_store_dir(parent).map_err(ArtifactError::Write)?;
        }
        let temp = path.with_extension("tmp");
        tokio::fs::write(&temp, blob)
            .await
            .map_err(ArtifactError::Write)?;
        tokio::fs::rename(&temp, path)
            .await
            .map_err(ArtifactError::Write)?;
        Ok(())
    }
}

/// The `(mtime, len)` freshness stamp read off one already-obtained metadata handle.
fn stamp_of(meta: &std::fs::Metadata) -> Option<(SystemTime, u64)> {
    meta.modified().ok().map(|mtime| (mtime, meta.len()))
}

/// Why the signed roster artifact could not be read or written.
#[derive(Debug, thiserror::Error)]
pub enum ArtifactError {
    /// The artifact could not be read.
    #[error("reading the signed roster")]
    Read(#[source] io::Error),
    /// The artifact could not be written.
    #[error("writing the signed roster")]
    Write(#[source] io::Error),
}

#[cfg(test)]
#[path = "artifact_tests.rs"]
mod artifact_tests;
