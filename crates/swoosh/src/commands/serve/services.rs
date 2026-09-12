use tightbeam::open_policy::Never;
use tightbeam::tunnel::{BoxRead, BoxWrite, Handler, ServeError, Served, ServiceCatalog};
use tokio::io::AsyncWriteExt as _;

/// The `control.services` handler swoosh injects: the node-lifecycle READ. It holds a pre-cut
/// [`ServiceCatalog`] snapshot (the names + effective posture of what this node serves, taken once at serve
/// start from the resolved routes and the base gate) and, on an admitted stream, writes its
/// self-delimiting encoding and closes. A pure READ: no mutable state, no
/// [`CancellationToken`](tightbeam::tunnel::CancellationToken), no authority granted, so a popped courier
/// leaks only a member-known service menu, never a lever on the node.
///
/// MEMBER-only (`type Exposure = Never`, and the route is declared member-only where `serve` assembles it):
/// the service menu is member-only (delib-18 containment), so a stranger is refused at the gate and a
/// delegate the gate admitted by slip is refused at the route floor, both before any `Response::Ok` and
/// neither ever learning what the node serves. The blob is self-delimiting (a count then length-prefixed
/// entries), so the handler just writes it and closes the write half, the same shape the `roster:` handler
/// uses for its signed membership snapshot.
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
    // The route is member-only (declared in `serve`): the served-service menu is revealed only to a
    // whole-node member (delib-18 containment), and the marker keeps an open-gate pairing unbuildable.
    type Exposure = Never;

    async fn serve(
        &self,
        _served: Served<Self>,
        mut writer: BoxWrite,
        _reader: BoxRead,
    ) -> Result<(), ServeError> {
        writer.write_all(&self.catalog.encode()).await?;
        writer.shutdown().await?;
        Ok(())
    }
}
