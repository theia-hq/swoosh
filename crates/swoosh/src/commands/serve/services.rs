use nauthy::Admitted;
use tightbeam::open_policy::Never;
use tightbeam::tunnel::{BoxRead, BoxWrite, Handler, ServiceCatalog};
use tokio::io::AsyncWriteExt as _;

/// The `control.services` handler swoosh injects: the node-lifecycle READ. It holds a pre-cut
/// [`ServiceCatalog`] snapshot (the names + effective posture of what this node serves, taken once at serve
/// start from the parsed services and the resolved gate) and, on an admitted stream, writes its
/// self-delimiting encoding and closes. A pure READ: no mutable state, no
/// [`CancellationToken`](tightbeam::tunnel::CancellationToken), no authority granted, so a popped courier
/// leaks only a member-known service menu, never a lever on the node.
///
/// GATED (`type Public = Never`): the service menu is member-only (delib-18 containment), so a stranger is
/// refused at the gate and never learns what the node serves. The blob is self-delimiting (a count then
/// length-prefixed entries), so the handler just writes it and closes the write half, the same shape the
/// `roster:` handler uses for its signed membership snapshot.
///
/// Public so the `control.services` integration proof drives the SAME handler `serve` injects, not a
/// hand-rolled near-copy (as `gated_stop` reuses `Stop`).
pub struct ServiceList {
    catalog: ServiceCatalog,
}

impl ServiceList {
    /// Build the `control.services` handler over the pre-cut catalog snapshot it serves.
    pub fn new(catalog: ServiceCatalog) -> Self {
        Self { catalog }
    }
}

impl Handler for ServiceList {
    // GATED: the served-service menu is member-only (delib-18: existence and shape revealed only after
    // admission), so no legitimate public use.
    type Public = Never;

    async fn serve(
        &self,
        _admitted: Admitted,
        mut writer: BoxWrite,
        _reader: BoxRead,
    ) -> eyre::Result<()> {
        writer.write_all(&self.catalog.encode()).await?;
        writer.shutdown().await?;
        Ok(())
    }
}
