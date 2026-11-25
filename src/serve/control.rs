//! The routes every `serve` binds that no entry names: the node's own, dotted so no name a person types can
//! be one. Each route's handler lives in the file named for the route, and is reached by its path
//! (`control::Serve`, `control::Sync`, `control::Renewal`), never imported bare: a bare `Sync` shadows the
//! prelude's marker trait, and a bare `Serve` tightbeam's, and the shadow is a build error at any use
//! beside it.

use std::sync::Arc;

use nauthy::Denylist;
use tightbeam::tunnel::{CancellationToken, Router, ServiceCatalog};

use super::{
    CONTROL_SERVE_SERVICE, LOOKUP_ROOT_SERVICE, RENEWAL_SERVICE, SYNC_SERVICE, StopSource, lookup,
};
use crate::home::Home;

mod renewal;
mod serve;
mod sync;

pub use renewal::{Known, Renewal};
pub use serve::{Answer, FirstRound, Hold, REQUEST_DEADLINE, Request, Serve};
pub use sync::Sync;

/// Bind `control.serve` ([`CONTROL_SERVE_SERVICE`]) member-only, over the catalog cut here, once, from the
/// routes `router` holds: call it after every other route and both open overlays are declared, so the
/// catalog lists them all. `control.serve` lists itself. Returns the catalog for the resident's list, and
/// the [`FirstRound`] whose hold a stop waits on.
///
/// Member-only (`member_service`), so the gate's badge and tightbeam's member floor both stand before any
/// `Response::Ok`: a stranger and a delegate's slip are refused there and never reach the handler. A stop
/// is stopped through `cancel` and noted in `stop_source`; `revoked` is the store the gate reads, asked
/// again at a stop.
pub fn bind_serve(
    router: Router,
    cancel: CancellationToken,
    stop_source: Arc<StopSource>,
    revoked: Arc<Denylist>,
) -> eyre::Result<(Router, ServiceCatalog, FirstRound)> {
    let name = CONTROL_SERVE_SERVICE.parse()?;
    let catalog = router.catalog(Some(CONTROL_SERVE_SERVICE.parse()?));
    let (first_round, hold) = FirstRound::new();
    let handler = Serve::new(catalog.clone(), cancel, stop_source, hold, revoked);
    let router = router.member_service(name, handler)?;
    Ok((router, catalog, first_round))
}

/// Bind the routes every `serve` exchanges with other machines on, whatever the standing: the update
/// route ([`SYNC_SERVICE`]) member-gated, then the pick-up route ([`RENEWAL_SERVICE`]) and the root route
/// ([`LOOKUP_ROOT_SERVICE`]) proven-only, each answering from `home`. The keys the two proven routes
/// answer are read once here into the returned [`Watched`]; the caller keeps them fresh with
/// [`Known::watch`] and [`lookup::Devices::watch`] for as long as it serves.
pub async fn bind_exchanges(router: Router, home: &Home) -> eyre::Result<(Router, Watched)> {
    // Member-gated: only this root's devices exchange updates.
    let router = router.member_service(SYNC_SERVICE.parse()?, Sync::new(home.clone()))?;
    // Bound on every `serve` so a `join` under a running one needs no restart, but only while this home is
    // a device or holds its root, and its update verifies under the pin, does any key reach the handler: a
    // key the update lists live.
    let known = Known::load(home).await;
    let knows = known.clone();
    let router = router.proven_service(
        RENEWAL_SERVICE.parse()?,
        Renewal::new(home.clone()),
        move |key| knows.knows(key),
    )?;
    // A peer this home saves as one machine of a person asks which root vouches for this machine; every
    // other key misses before it takes a slot.
    let devices = lookup::Devices::load(home).await;
    let saved = devices.clone();
    let router = router.proven_service(
        LOOKUP_ROOT_SERVICE.parse()?,
        lookup::Root::new(home.clone()),
        move |key| saved.knows(key),
    )?;
    Ok((router, Watched { known, devices }))
}

/// What [`bind_exchanges`] read for its two proven routes, which `serve` keeps fresh while it runs.
pub struct Watched {
    /// The keys the pick-up route answers.
    pub known: Known,
    /// The keys the root route answers.
    pub devices: lookup::Devices,
}
