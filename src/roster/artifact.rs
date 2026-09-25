//! The update held in the node home, `<home>/roster`, and the fork kept beside it, `<home>/roster.fork`.
//!
//! Only a fold writes either ([`fold`](super::fold)), and an exchange reads `roster` afresh each time it
//! answers, so an update folded while `serve` runs is the one it gives next, with no restart.

use std::io;
use std::path::Path;

/// Write `blob`, a signed update, to `path`, replacing what was there.
///
/// Written to a sibling temp and renamed over the target, so a reader sees the old update or the new one,
/// never a torn one. An update is handed to every device, so it takes no private mode.
pub(crate) async fn write(path: &Path, blob: &[u8]) -> Result<(), ArtifactError> {
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

/// Why an update could not be written.
#[derive(Debug, thiserror::Error)]
pub enum ArtifactError {
    /// The update could not be written.
    #[error("writing the update")]
    Write(#[source] io::Error),
}
