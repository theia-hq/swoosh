//! The update held in the node home, `<home>/roster`, and the fork kept beside it, `<home>/roster.fork`.
//!
//! Only a fold writes either ([`fold`](super::fold), and [`fold_fork`](super::fold_fork) for the fork),
//! and an exchange reads `roster` afresh each time it answers, so an update folded while `serve` runs is
//! the one it gives next, with no restart.

use std::path::Path;

/// Write `blob`, a signed update, to `path`, replacing what was there.
///
/// Written through [`write_private_atomic`](crate::config::write_private_atomic): an owner-only temp unique
/// to this write, synced, renamed over the target, then the directory synced. A reader sees the old update
/// or the new one, never a torn one, and the update is on disk before any offer of it is made.
pub(crate) async fn write(path: &Path, blob: &[u8]) -> Result<(), ArtifactError> {
    crate::config::write_private_atomic(path, blob)
        .await
        .map_err(ArtifactError::Write)
}

/// Why an update could not be written.
#[derive(Debug, thiserror::Error)]
pub enum ArtifactError {
    /// The update could not be written.
    #[error("writing the update")]
    Write(#[source] eyre::Report),
}
