//! `swoosh invite rm <label>`: cancel an invite by revoking its badge now.
//!
//! Cancel is not deletion: the badge's ROOT revocation id is written to this node's denylist, so every
//! gate reading it refuses the badge on the next dial, and the mint-log ledger row STAYS for audit (the
//! badge's expiry was its only self-life). The `me/<label>` contact is left alone too: cancelling trust
//! is not forgetting a name (`swoosh contact rm me/<label>` does that).
//!
//! A label resolves through the `me` partition exactly as `invite add` recorded it; a raw device key is
//! accepted as the canonical handle. A label with no membership row points at `grant revoke`, because a
//! service grant is a different object.

use bifrost::NodeId;
use clap::Args;
use nauthy::{FileDenylist, RevocationId};
use swoosh::contacts::{ContactRef, Contacts};
use swoosh::grants::{GrantTarget, Grants};
use swoosh::home::Home;

/// Cancel an invite by revoking its badge.
#[derive(Debug, Args)]
pub struct RmCmd {
    /// the invite label you gave `invite add`, or the raw device key it admits
    #[arg(value_name = "label")]
    pub label: String,
}

impl RmCmd {
    /// Revoke every membership badge recorded for the resolved device into the persisted denylist.
    pub async fn run(self, contacts: &Contacts, home: &Home) -> eyre::Result<()> {
        let holder = self.holder(contacts)?;
        let ledger = Grants::at(home.links());
        let records: Vec<_> = ledger
            .load()
            .await?
            .into_iter()
            .filter(|record| {
                record.target == GrantTarget::Membership && record.holder == holder.to_string()
            })
            .collect();
        if records.is_empty() {
            eyre::bail!(
                "no invite recorded for `{}` in the ledger ({}); list yours with `swoosh invite ls`, or \
                 cut a service grant with `swoosh grant revoke {}`",
                self.label,
                ledger.path().display(),
                self.label
            );
        }
        // Revoke each matching badge at its root, the same offline file-write `grant revoke` performs. A
        // device re-invited several times holds several rows, and cancelling the label cuts them all.
        let revoked = home.revoked();
        if let Some(parent) = revoked.parent() {
            swoosh::config::create_store_dir(parent)?;
        }
        let mut denylist = FileDenylist::load(revoked).await?;
        for record in &records {
            denylist
                .revoke_id(RevocationId::clone(&record.root_id))
                .await?;
        }
        println!(
            "revoked {} badge(s) for {} ({})",
            records.len(),
            self.label,
            denylist.path().display()
        );
        Ok(())
    }

    /// Resolve the target to the canonical device key: a raw node id is used verbatim, else the label is
    /// looked up under `me/`, where `invite add` recorded it.
    fn holder(&self, contacts: &Contacts) -> eyre::Result<NodeId> {
        if let Ok(node) = self.label.parse::<NodeId>() {
            return Ok(node);
        }
        let reference: ContactRef = format!("me/{}", self.label).parse().map_err(|_| {
            eyre::eyre!(
                "`{}` is not an invite label; pass the label you gave `invite add`, or the raw device key",
                self.label
            )
        })?;
        let candidates = match contacts.resolve_candidates(&reference) {
            Ok(candidates) => candidates,
            Err(_) => {
                eyre::bail!(
                    "no invite named `{}`; list yours with `swoosh invite ls`",
                    self.label
                )
            }
        };
        match candidates.as_slice() {
            [one] => Ok(one.node),
            _ => eyre::bail!(
                "no invite named `{}`; list yours with `swoosh invite ls`",
                self.label
            ),
        }
    }
}
