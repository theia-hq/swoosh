//! `swoosh grant share <service>`: mint a `sheer:` capability link for one of this node's services.
//!
//! A local verb: it signs with this node's persisted identity (the key an exposed service roots at) but
//! binds no transport and reaches nobody. Wraps tightbeam's [`ShareCmd`] in-process, so the link a peer
//! presents to `swoosh tunnel expose` roots at the same key swoosh serves under. Minting is offline: hand
//! the link to a peer and they connect directly, no allowlist to keep in sync.

use std::path::Path;

use clap::Args;
use tightbeam::ShareCmd as Inner;

use crate::identity::{self, Identity};

/// Mint a `sheer:` capability link granting one service, expiring, attenuable, delegable.
// `group(skip)`: this wrapper only re-parents tightbeam's identically-named `ShareCmd`, so its implicit
// clap arg group would collide with the inner's (both default to the ident `ShareCmd`). It groups nothing
// of its own, so skipping its group is both correct and what clears the collision.
#[derive(Debug, Args)]
#[group(skip)]
pub struct ShareCmd {
    #[command(flatten)]
    inner: Inner,
}

impl ShareCmd {
    /// Sign the link under swoosh's persisted identity and print it.
    pub async fn run(self, key: Option<&Path>) -> eyre::Result<()> {
        // The link roots at swoosh's stable key (the one an exposed service is reached at), so resolve the
        // persisted identity, creating one on first use exactly as `swoosh identity` would.
        let secret = identity::resolve(Identity::Persisted, key).await?;
        self.inner.run(&secret.cap_identity()?)
    }
}
