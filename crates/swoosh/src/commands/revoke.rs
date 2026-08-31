//! `swoosh grant revoke <link>`: revoke a `sheer:` capability so this node refuses it, offline and at once.
//!
//! A local verb: no identity, no transport. It opens swoosh's OWN revocation denylist (dir-derived from
//! `--key` like the rest of swoosh's store) and hands it to the tunnel core's [`revoke_into`], which adds
//! the cap's id by value and never reaches a config path. The next `swoosh tunnel expose` reads the same
//! denylist, so a revoked link is refused at once rather than waiting for its expiry.

use std::path::Path;

use clap::Args;
use nauthy::Denylist;

/// Revoke a `sheer:` link so this node refuses it at once, without waiting for expiry.
#[derive(Debug, Args)]
pub struct RevokeCmd {
    /// The `sheer:` link to revoke (revokes it and everything attenuated from it).
    #[arg(value_name = "link")]
    pub link: String,
}

impl RevokeCmd {
    /// Add the cap's revocation id to swoosh's persisted denylist, under the same `--key` dir the expose
    /// gate reads. Opens the denylist as a value and passes it by ref to the core, which never reads a path.
    pub async fn run(self, key: Option<&Path>) -> eyre::Result<()> {
        let mut denylist = Denylist::load(crate::config::revoked_path(key)?).await?;
        tightbeam::tunnel::revoke_into(&mut denylist, &self.link).await?;
        println!("revoked ({})", denylist.path().display());
        Ok(())
    }
}
