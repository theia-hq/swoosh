//! `swoosh grant revoke <link>`: revoke a `sheer:` capability so this node refuses it, offline and at once.
//!
//! A local verb: no identity, no transport. Wraps tightbeam's [`RevokeCmd`] in-process; it adds the cap's
//! id to this node's persisted denylist, which the next `swoosh tunnel expose` reads, so a revoked link
//! is refused at once rather than waiting for its expiry.

use clap::Args;
use tightbeam::RevokeCmd as Inner;

/// Revoke a `sheer:` link so this node refuses it at once, without waiting for expiry.
// `group(skip)`: a pass-through wrapper over tightbeam's identically-named `RevokeCmd`, so its implicit
// arg group would collide with the inner's. It groups nothing, so skipping clears the collision cleanly.
#[derive(Debug, Args)]
#[group(skip)]
pub struct RevokeCmd {
    #[command(flatten)]
    inner: Inner,
}

impl RevokeCmd {
    /// Add the cap's revocation id to the persisted denylist.
    pub async fn run(self) -> eyre::Result<()> {
        self.inner.run().await
    }
}
