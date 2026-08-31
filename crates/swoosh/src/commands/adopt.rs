//! `swoosh adopt <authkey>`: become the derived identity and trust the signet that minted it.
//!
//! The other half of `mint`: on the MACHINE (a CI runner, a new laptop), `adopt` writes the authkey's
//! child seed as SWOOSH's persisted identity, so it comes up AS the derived device, and records the signet
//! its gate trusts, so `swoosh tunnel expose` admits the owner's own devices and anyone they delegate to. A
//! local verb: no transport, no reach. The identity lands in swoosh's own store (`~/.config/swoosh/`, or
//! `--key`/`SWOOSH_KEY`) -- the SAME store `swoosh tunnel expose`/`serve` bind under -- so the exposed node
//! id matches the contact `mint` recorded. The signet lands beside it in swoosh's own config, under the
//! same `--key` dir, where the expose gate reads it.

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
    /// Parse the authkey, write the child seed as this node's identity, and record the trusted signet.
    pub async fn run(self, key: Option<&Path>) -> eyre::Result<()> {
        let authkey::Authkey {
            mut seed,
            signet,
            badge,
        } = authkey::parse(&self.authkey)?;
        // Compute the adopted node id before wiping the seed, for the confirmation line.
        let node = NodeId::from_ed25519_secret(&seed);
        // Become the derived device: write the child seed as SWOOSH's persisted identity -- the SAME store
        // `swoosh tunnel expose`/`serve` bind under (crate::identity::resolve), so this node comes up AS the
        // adopted device. Writing tightbeam's separate store was the bug: `swoosh tunnel expose` binds
        // swoosh's key, so the exposed node had a different id than the contact pointed at, and was never
        // reachable. Then wipe our copy.
        crate::identity::write(&seed, key).await?;
        seed.zeroize();
        // Trust the signet: the default gate admits its devices (members) and delegates (slips). The signet
        // lands beside the identity just written, under the SAME `--key` dir, in swoosh's own config, which
        // `swoosh tunnel expose` reads via `crate::config::load_signet`. One command, one dir.
        crate::config::write_signet(key, signet).await?;
        // Store the signet-signed membership badge beside the seed, so this device PRESENTS the badge the
        // signet minted for it (rooted at the signet, bound to this key) when it dials a family-gated node,
        // rather than self-signing (which roots at this child key and is refused). Absent for a legacy
        // two-field authkey; then the device falls back to self-signing (only useful for the signet holder).
        if let Some(badge) = &badge {
            crate::config::write_badge(key, badge).await?;
        }

        println!("adopted this machine as {}  [mine]", node.short());
        println!(
            "trusting signet {}: `swoosh tunnel expose` now admits its members and delegates.",
            signet.short()
        );
        if badge.is_some() {
            println!("stored your membership badge: this device now reaches your gated services.");
        }
        Ok(())
    }
}
