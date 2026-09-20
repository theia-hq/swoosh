//! `adopt`'s badge guard, which is a DOWNGRADE check and not a difference check: the quarterly renewal
//! lands with no flag, and every shape that is not an improvement on what is stored still takes one.
//!
//! The predicate is what makes "re-run `invite add`" the whole renewal mechanism. If it refused every
//! differing badge, the routine act would need the `--force` that also disables the re-root guard, so
//! the safe act would demand the dangerous flag every quarter.

use core::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use swoosh::identity::Secret;

use super::*;

/// A day, the unit the badge's life is measured in.
const DAY: Duration = Duration::from_secs(24 * 60 * 60);

/// A fixed instant, so no case races the wall clock.
fn base() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_788_400_000)
}

/// A real signet-signed membership badge for `device`, expiring at `expiry`. Really signed and really
/// parsed, so a case cannot pass against a stand-in the predicate would never meet in the field.
fn badge_for(signet: &Secret, device: NodeId, expiry: SystemTime) -> Link {
    signet
        .cap_identity()
        .expect("the signet is a cap identity")
        .mint_member(device.verify_key(), expiry)
        .expect("mint a device badge")
        .seal()
        .expect("seal the badge")
        .link()
        .expect("the badge renders as a link")
}

/// THE renewal: the same signet re-signs the same device for a later date, and it is accepted with no
/// flag. This is the whole reason there is no renew verb; without it the operator reaches for `--force`
/// four times a year and disables the re-root guard each time.
#[test]
fn a_later_badge_from_the_same_signet_for_the_same_device_renews() {
    let signet = Secret::ephemeral();
    let device = Secret::ephemeral().node_id();
    let stored = badge_for(&signet, device, base() + 10 * DAY);
    let fresh = badge_for(&signet, device, base() + 100 * DAY);

    assert!(
        renews(&stored, &fresh, device).expect("the predicate reads both badges"),
        "a strictly later badge at the same signet for the same device is a renewal"
    );
}

/// The replay the guard exists for: an OLD token presented again under the live signet. It is by
/// construction not later, so it is refused, and `--force` stays the only way to store it.
#[test]
fn an_older_badge_replayed_under_the_same_signet_is_not_a_renewal() {
    let signet = Secret::ephemeral();
    let device = Secret::ephemeral().node_id();
    let stored = badge_for(&signet, device, base() + 100 * DAY);
    let replay = badge_for(&signet, device, base() + 10 * DAY);

    assert!(
        !renews(&stored, &replay, device).expect("the predicate reads both badges"),
        "an earlier badge is a downgrade, whoever signed it"
    );
}

/// A badge from ANOTHER signet is never a renewal, however long it runs. `admit_signet` already refuses
/// the re-root, and this keeps the two guards from disagreeing about the same token.
#[test]
fn a_badge_from_another_signet_is_not_a_renewal() {
    let device = Secret::ephemeral().node_id();
    let stored = badge_for(&Secret::ephemeral(), device, base() + 10 * DAY);
    let foreign = badge_for(&Secret::ephemeral(), device, base() + 100 * DAY);

    assert!(
        !renews(&stored, &foreign, device).expect("the predicate reads both badges"),
        "a later badge at a DIFFERENT root re-roots this machine; it does not renew it"
    );
}

/// The derived-invite case: a badge bound to a DIFFERENT device is not a renewal of this one, even from
/// the same signet and even expiring later. Adopting a derived invite replaces the machine's whole
/// identity, and that must not slip through as routine maintenance of the outgoing device's credential.
#[test]
fn a_badge_bound_to_another_device_is_not_a_renewal() {
    let signet = Secret::ephemeral();
    let stored_device = Secret::ephemeral().node_id();
    let other_device = Secret::ephemeral().node_id();
    let stored = badge_for(&signet, stored_device, base() + 10 * DAY);
    let incoming = badge_for(&signet, other_device, base() + 100 * DAY);

    assert!(
        !renews(&stored, &incoming, other_device).expect("the predicate reads both badges"),
        "the stored badge binds a different device, so this replaces an identity rather than renewing \
         a credential"
    );
}

/// An EXPIRED stored badge still renews: the device that let its badge lapse is exactly the one being
/// re-invited, and asking its binding question at an instant inside its own life is what lets a dead
/// badge still answer it. Without that, the quarterly cadence would work only if never missed.
#[test]
fn an_expired_stored_badge_is_still_renewed_without_a_flag() {
    let signet = Secret::ephemeral();
    let device = Secret::ephemeral().node_id();
    let stored = badge_for(&signet, device, SystemTime::now() - 6 * DAY);
    let fresh = badge_for(&signet, device, SystemTime::now() + 90 * DAY);

    assert!(
        renews(&stored, &fresh, device).expect("the predicate reads both badges"),
        "a lapsed device renews with no flag, or a missed quarter costs the danger flag"
    );
}

/// The expiry comparison itself, at every boundary including the two nauthy alone can produce. An
/// unreadable expiry (a badge minted before badges carried the advisory fact) can never be proven to
/// outlive anything, so the pair falls back to the byte-inequality refusal rather than to acceptance.
#[test]
fn only_a_strictly_later_readable_expiry_supersedes() {
    let early = base();
    let late = base() + DAY;

    assert_eq!(
        superseded(Some(early), Some(late)),
        Some(early),
        "later supersedes, and hands back the instant the stored badge was last alive"
    );
    assert_eq!(
        superseded(Some(late), Some(early)),
        None,
        "earlier does not"
    );
    assert_eq!(
        superseded(Some(early), Some(early)),
        None,
        "equal is not strictly later: a verbatim replay must not pass as an improvement"
    );
    assert_eq!(
        superseded(None, Some(late)),
        None,
        "an unreadable STORED expiry cannot be beaten, so the old guard stands"
    );
    assert_eq!(
        superseded(Some(early), None),
        None,
        "an unreadable INCOMING expiry proves nothing, so it is not accepted"
    );
    assert_eq!(superseded(None, None), None);
}
