//! `swoosh adopt <authkey>`: become the derived identity and trust the signet that minted it.
//!
//! The other half of `mint`: on the MACHINE (a CI runner, a new laptop), `adopt` writes the authkey's
//! child seed as this node's identity, so it comes up AS the derived device, and records the signet as
//! the anchor its gate trusts, so `tightbeam expose` admits the owner's own devices and anyone they
//! delegate to. A local verb: no transport, no reach. It provisions the tightbeam node this machine
//! exposes under (honoring `TIGHTBEAM_KEY` / `TIGHTBEAM_ANCHOR`, or the default with `--key`), which is
//! the identity `expose` binds and the anchor `expose` reads.

use std::path::Path;

use bifrost::NodeId;
use clap::Args;
use zeroize::Zeroize as _;

use crate::authkey;

/// Adopt a minted authkey: become that device identity and trust its signet.
#[derive(Debug, Args)]
pub struct AdoptCmd {
    /// the authkey minted for this machine (a SECRET: adopting it becomes this identity)
    #[arg(value_name = "authkey")]
    pub authkey: String,
}

impl AdoptCmd {
    /// Parse the authkey, write the child seed as this node's identity, and record the signet anchor.
    pub async fn run(self, key: Option<&Path>) -> eyre::Result<()> {
        let (mut seed, signet) = authkey::parse(&self.authkey)?;
        // Compute the adopted node id before wiping the seed, for the confirmation line.
        let node = NodeId::from_ed25519_secret(&seed);
        // Become the derived device: write the child seed as the tightbeam identity this machine exposes
        // under, then wipe our copy.
        tightbeam::identity::write(&seed, key).await?;
        seed.zeroize();
        // Trust the signet: `expose`'s default gate admits its devices (members) and delegates (slips).
        tightbeam::config::write_anchor(signet).await?;

        println!("adopted this machine as {}  [mine]", node.short());
        println!(
            "trusting signet {} \u{2014} `tightbeam expose` now admits its members and delegates.",
            signet.short()
        );
        Ok(())
    }
}
