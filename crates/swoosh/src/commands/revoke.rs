//! `swoosh grant revoke <peer|link>`: revoke a grant so this node refuses it, offline and at once.
//!
//! One verb, two objects. Given a `sheer:` LINK, it revokes exactly that link and everything attenuated from
//! it, the way pasting the link back always has (tightbeam's [`revoke_into`](tightbeam::tunnel::revoke_into),
//! unchanged). Given a PEER instead (a node id or a `petname/device` you granted), it looks that holder up in
//! swoosh's own mint-log ledger, takes the ROOT revocation id recorded when the grant was issued, and revokes
//! at the root, cutting off the grant AND everything the holder delegated from it. Either way it writes
//! swoosh's OWN denylist (dir-derived from `--key` like the rest of the store); the next `swoosh serve` reads
//! the same denylist, so the grant is refused at once rather than waiting for expiry.

use std::path::Path;

use clap::Args;
use nauthy::{FileDenylist, RevocationId};

use crate::contacts::{ContactRef, Contacts, ContactsStore};
use crate::grants::{self, Grants};

/// Revoke a grant so this node refuses it at once, without waiting for expiry.
///
/// The object is either a `sheer:` link (revokes that link and everything attenuated from it) or a peer you
/// granted (a node id or `petname/device`; revokes every grant issued to that holder, at its root, so all
/// delegations fall with it).
#[derive(Debug, Args)]
pub struct RevokeCmd {
    /// A `sheer:` link to revoke, or a peer you granted (a node id or `petname/device`) to cut off.
    #[arg(value_name = "peer|link")]
    pub target: String,
}

impl RevokeCmd {
    /// Revoke the target into swoosh's persisted denylist under the same `--key` dir the expose gate reads.
    /// A `sheer:` target takes the link path; anything else is a holder looked up in the ledger. Reads the
    /// address book only to resolve a petname holder to its canonical node id (the link path never does).
    pub async fn run(self, store: ContactsStore, key: Option<&Path>) -> eyre::Result<()> {
        let mut denylist = FileDenylist::load(crate::config::revoked_path(key)?).await?;
        // A `sheer:` prefix is the one unambiguous mark of a link: parse-don't-validate on the object's shape.
        // A malformed link still routes here (and fails as a bad link), rather than being misread as a peer.
        if self.target.starts_with(nauthy::SCHEME) {
            tightbeam::tunnel::revoke_into(&mut denylist, &self.target).await?;
            println!("revoked link ({})", denylist.path().display());
            return Ok(());
        }
        // `-` is the ledger's placeholder for a bearer grant's (absent) holder, never a revoke target: a
        // bearer link has no holder to name, and treating `-` as one would mass-revoke every bearer grant.
        // Refuse it and point at the real ways to revoke a bearer link.
        if self.target == grants::ANYONE {
            eyre::bail!(
                "`-` is the placeholder for a bearer grant's holder, not a revoke target: a bearer link has \
                 no holder to name. Paste the `sheer:` link to `swoosh grant revoke <link>`, or run \
                 `swoosh grant ls`"
            );
        }
        self.revoke_holder(&mut denylist, store.contacts(), key)
            .await
    }

    /// Revoke every grant issued to a holder by its ROOT revocation id, read from the mint-log ledger. The
    /// ledger is the issuer-side index that makes this possible: the link itself left this machine long ago,
    /// but its root id was recorded here, and revoking the root kills the grant and all its delegations.
    ///
    /// The ledger records a bound grant's holder by its CANONICAL device node id, so this matches the target
    /// against that node id whether the issuer typed the raw key or a petname: a `petname/device` (or a bare
    /// petname for a whole person) is resolved through the address book to the node id(s) it names, and a
    /// record matches on the literal target OR any resolved node id.
    async fn revoke_holder(
        self,
        denylist: &mut FileDenylist,
        contacts: &Contacts,
        key: Option<&Path>,
    ) -> eyre::Result<()> {
        let ledger = Grants::at(crate::config::grants_path(key)?);
        let records = ledger.load().await?;
        // The holder strings that count as a hit: the literal target, plus the canonical node id of every
        // device it resolves to (an unknown petname resolves to nothing, leaving just the literal).
        let mut wanted = vec![String::clone(&self.target)];
        if let Ok(contact) = self.target.parse::<ContactRef>()
            && let Ok(candidates) = contacts.resolve_candidates(&contact)
        {
            wanted.extend(
                candidates
                    .into_iter()
                    .map(|candidate| candidate.node.to_string()),
            );
        }
        let matches: Vec<&_> = records
            .iter()
            .filter(|record| wanted.contains(&record.holder))
            .collect();
        if matches.is_empty() {
            eyre::bail!(
                "no grant issued to `{}` is recorded in the ledger ({}); paste the `sheer:` link to revoke \
                 one directly, or run `swoosh grant ls` to see who you have granted",
                self.target,
                ledger.path().display()
            );
        }
        // Revoke each matching grant at its root. A holder may hold several grants (say `ssh` and `web`);
        // naming the holder cuts off all of them, which is what revoking a peer means.
        for record in &matches {
            denylist
                .revoke_id(RevocationId::clone(&record.root_id))
                .await?;
        }
        println!(
            "revoked {} grant(s) to {} ({})",
            matches.len(),
            self.target,
            denylist.path().display()
        );
        Ok(())
    }
}
