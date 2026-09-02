use std::sync::Arc;

use nauthy::Admitted;
use tightbeam::open_policy::Never;
use tightbeam::tunnel::{BoxRead, BoxWrite, Handler};
use tokio::io::AsyncWriteExt as _;

/// The `roster:` handler: serve the signet-signed membership snapshot to an admitted member, then close.
/// GATED (a stranger must never read the member set: delib-28 containment). Only the signet SIGNED the blob;
/// this node merely serves a pre-cut snapshot, so a popped courier leaks a read of a member-known set, never
/// authority (the signing secret is not needed to serve, only to have signed). The blob is self-delimiting
/// and signature-validated by the puller, so the handler just writes it and closes the write half.
pub struct Roster {
    blob: Arc<Vec<u8>>,
}

impl Roster {
    /// Build the `roster:` handler over the pre-cut, signet-signed membership snapshot it serves.
    pub fn new(blob: Arc<Vec<u8>>) -> Self {
        Self { blob }
    }
}

impl Handler for Roster {
    // GATED (a stranger must never read the member set: delib-28 containment): no legitimate public use.
    type Public = Never;

    async fn serve(
        &self,
        _admitted: Admitted,
        mut writer: BoxWrite,
        _reader: BoxRead,
    ) -> eyre::Result<()> {
        writer.write_all(&self.blob).await?;
        writer.shutdown().await?;
        Ok(())
    }
}
