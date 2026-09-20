use std::sync::Arc;

use tightbeam::open_policy::Never;
use tightbeam::tunnel::{BoxRead, BoxWrite, Handler, ServeError, Served};
use tokio::io::AsyncWriteExt as _;

use crate::roster::Artifact;

/// The `roster:` handler: serve the signet-signed membership snapshot to an admitted member, then close.
/// GATED, because a stranger must never read the member set. This node only RELAYS bytes the signet
/// signed on its own machine when the membership last changed, so a popped courier leaks a read of a
/// member-known set, never authority: the signing secret is not needed to serve, and is deliberately not
/// present. The blob is self-delimiting and signature-validated by the puller, so the handler just writes
/// it and closes the write half.
///
/// The artifact is re-read per stream (a debounced stat, see [`Artifact`]), so a device invited while
/// this node is serving is in the very next pull with no restart. Before the signet has cut anything the
/// artifact is empty, and the handler writes those zero bytes rather than inventing a refusal: the
/// puller's [`verify`](crate::roster::verify) already names an empty read as its own condition, distinct
/// from a bad signature, and a host-side refusal would reach the dialer as the same clean EOF anyway.
pub struct Roster {
    artifact: Arc<Artifact>,
}

impl Roster {
    /// Build the `roster:` handler over the home's signed roster artifact.
    pub fn new(artifact: Arc<Artifact>) -> Self {
        Self { artifact }
    }
}

impl Handler for Roster {
    // GATED, because a stranger must never read the member set: no legitimate public use.
    type Exposure = Never;

    async fn serve(
        &self,
        _served: Served<Self>,
        mut writer: BoxWrite,
        _reader: BoxRead,
    ) -> Result<(), ServeError> {
        // Read the blob out of the oracle BEFORE the first await: `bytes` takes the state lock, and the
        // `Arc` is what lets it be released before the write.
        let blob = self.artifact.bytes();
        writer.write_all(&blob).await?;
        writer.shutdown().await?;
        Ok(())
    }
}
