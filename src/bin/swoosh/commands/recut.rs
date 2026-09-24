//! Re-cutting `<home>/roster` after a verb changed the fleet's membership.
//!
//! Freshness is plumbing, not a thing to ask a person to do, so there is no `fleet cut` verb: every verb
//! that changes the `me/*` member set calls this on its way out, and the next pull sees the new fleet
//! with no restart and no second command. This is also the ONE place a roster is signed, so the rule
//! "only the machine holding the signet cuts" is enforced in one readable predicate instead of being
//! re-derived per verb.

use swoosh::contacts::Contacts;
use swoosh::home::Home;
use swoosh::roster::Artifact;
use swoosh::{config, identity};

/// Re-cut and re-sign the home's roster artifact from `contacts`, if this machine is entitled to.
///
/// Call it AFTER the contacts store is saved: the book is the source of truth for the version, so a
/// failure here leaves a home whose artifact lags a version it will catch up to on the next edit, never
/// an artifact ahead of the book (which would burn a version number on members nobody recorded).
///
/// Three silent no-ops, each because there is genuinely nothing to cut, not because the failure is being
/// swallowed:
///
/// - the book is unversioned, so it has no membership set worth publishing;
/// - this home has no identity key at all, so it is nobody's fleet;
/// - this machine does not hold the signet ([`config::holds_signet`]), so it is a MEMBER device. It must
///   not write an artifact here: a roster signed by a member's key is refused by every puller, and not
///   writing one is what makes a relay-only node physically unable to mis-cut. `serve` reads the SAME
///   predicate, so the two halves cannot drift into a node that cuts what it may not serve.
pub async fn after_membership_change(home: &Home, contacts: &Contacts) -> eyre::Result<()> {
    let Some(doc) = contacts.cut_roster()? else {
        return Ok(());
    };
    // Load, never create: editing an address book must not mint the root key a later `serve` would gate
    // a whole fleet on.
    let Some(secret) = identity::load(home).await? else {
        return Ok(());
    };
    if !config::holds_signet(home, secret.node_id()).await? {
        return Ok(());
    }
    Artifact::write(
        &home.roster(),
        &secret.with_bytes(nauthy::Identity::from_secret)?,
        &doc,
    )
    .await?;
    Ok(())
}

#[cfg(test)]
#[path = "recut_tests.rs"]
mod recut_tests;
