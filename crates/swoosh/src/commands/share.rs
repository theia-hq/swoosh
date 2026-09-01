//! `swoosh grant share <service>`: mint a `sheer:` capability link for one of this node's services.
//!
//! A local verb: it signs with this node's persisted identity (the key an exposed service roots at) but
//! binds no transport and reaches nobody. It calls tightbeam's [`mint_link`](tightbeam::tunnel::mint_link)
//! grant logic under swoosh's own key, so the link a peer presents to `swoosh serve` roots at the same key
//! swoosh serves under. Minting is offline: hand the link to a peer and they connect directly, no allowlist
//! to keep in sync.

use std::path::Path;

use clap::Args;
use nauthy::Service;
use tightbeam::duration::Lifetime;

use crate::identity::{self, Identity};

/// Mint a `sheer:` capability link granting one service, expiring, attenuable, delegable.
///
/// The link is rooted at this node's identity, so a connector needs no separate node id and the exposer
/// needs no allowlist to keep in sync. A holder can narrow it (`swoosh grant attenuate`) and hand it off
/// entirely offline; the exposer verifies the whole chain with no server in the loop.
#[derive(Debug, Args)]
pub struct ShareCmd {
    /// The service the link grants (as named in `serve`, e.g. `ssh`).
    #[arg(value_name = "service")]
    pub service: Service,
    /// How long the link is valid, e.g. `2h`, `30m`, `90s`. Short-expiry is the v1 revocation story.
    #[arg(long, value_name = "duration", default_value = "1h")]
    pub expires: Lifetime,
    /// allow the holder to narrow and re-share the link
    #[arg(long)]
    pub delegable: bool,
}

impl ShareCmd {
    /// Sign the link under swoosh's persisted identity and print it.
    pub async fn run(self, key: Option<&Path>) -> eyre::Result<()> {
        // The link roots at swoosh's stable key (the one an exposed service is reached at), so resolve the
        // persisted identity, creating one on first use exactly as `swoosh identity` would.
        let secret = identity::resolve(Identity::Persisted, key).await?;
        let link = tightbeam::tunnel::mint_link(
            &secret.cap_identity()?,
            &self.service,
            self.expires.duration(),
            self.delegable,
        )?;
        println!("{link}");
        Ok(())
    }
}
