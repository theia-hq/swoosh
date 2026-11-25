//! The routes every `serve` binds that no entry names: the node's own, dotted so no name a person types can
//! be one. Each route's handler lives in the file named for the route, and is reached by its path
//! (`control::Sync`, `control::Renewal`), never imported bare: a bare `Sync` shadows the prelude's marker
//! trait, and the shadow is a build error at any `Sync` bound beside it.

use tightbeam::tunnel::Router;

use super::{LOOKUP_ROOT_SERVICE, RENEWAL_SERVICE, SYNC_SERVICE, lookup};
use crate::home::Home;

mod renewal;
mod sync;

pub use renewal::{Known, Renewal};
pub use sync::Sync;

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
