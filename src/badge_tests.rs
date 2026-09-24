//! The badge's own reading of its remaining life: where the renewal window's edges fall, that an
//! unreadable expiry is its own state and never silently "fine", and that a dead badge still reports
//! when it died (which is exactly when its holder needs telling).

use core::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use super::{DEVICE_WARN_WINDOW, Expiry};
use crate::identity::{DEVICE_BADGE_TTL, Secret};

/// A day, the unit the window and the TTL are both expressed in.
const DAY: Duration = Duration::from_secs(24 * 60 * 60);

/// A fixed instant to classify against, so no case races the wall clock. Far enough past the epoch that
/// a case asking about a badge dead for days does not have to subtract below it.
fn now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_788_400_000)
}

/// The warning window is the last fortnight of the badge's life, well short of the whole of it: a
/// fresh badge is therefore `Live`, and the day it enters the window it starts saying so.
#[test]
fn the_window_is_fourteen_days_of_a_ninety_day_badge() {
    assert_eq!(DEVICE_WARN_WINDOW, 14 * DAY);
    assert_eq!(DEVICE_BADGE_TTL, 90 * DAY);
    assert!(
        DEVICE_WARN_WINDOW < DEVICE_BADGE_TTL,
        "a window at or past the TTL would warn from the moment the badge is minted, which warns about \
         nothing"
    );
}

/// Zero, one, many across the window's edges. A badge one second outside the window is `Live` and says
/// nothing; the window's own edge is inside it (the operator is warned on the boundary day, not after
/// it); a badge inside is `Expiring`.
#[test]
fn the_window_edge_is_inside_the_warning() {
    assert_eq!(
        Expiry::at(
            Some(now() + DEVICE_WARN_WINDOW + Duration::from_secs(1)),
            now()
        ),
        Expiry::Live {
            left: DEVICE_WARN_WINDOW + Duration::from_secs(1)
        },
        "a badge outside the window says nothing"
    );
    assert_eq!(
        Expiry::at(Some(now() + DEVICE_WARN_WINDOW), now()),
        Expiry::Expiring {
            left: DEVICE_WARN_WINDOW
        },
        "the boundary day warns: rounding it the other way silently costs the operator a day"
    );
    assert_eq!(
        Expiry::at(Some(now() + DAY), now()),
        Expiry::Expiring { left: DAY }
    );
}

/// A dead badge reports how long it has been dead. Reading a FACT evaluates no check, so the answer
/// survives the expiry, which is the whole point: the refusal that replaces the uniform `not admitted`
/// has to be able to say what happened and roughly when.
#[test]
fn an_expired_badge_still_reports_when_it_died() {
    assert_eq!(
        Expiry::at(Some(now() - 6 * DAY), now()),
        Expiry::Expired { ago: 6 * DAY }
    );
    // The instant of expiry itself is not yet past: the datalog check is `$t <= expiry`, so the badge is
    // still admissible at exactly that moment and this must not call it dead.
    assert_eq!(
        Expiry::at(Some(now()), now()),
        Expiry::Expiring {
            left: Duration::ZERO
        }
    );
}

/// A badge carrying no `expires_at` fact is its OWN state, never folded into "fine". Folding it into
/// `Live` would silently disarm every surface for exactly the badges minted before the fact existed.
#[test]
fn an_unreadable_expiry_is_its_own_state() {
    assert_eq!(Expiry::at(None, now()), Expiry::Unknown);
}

/// The rendered fragment every surface prints, in the same span vocabulary the issuer side already uses
/// (`grant ls` / `invite ls`), so one badge reads the same on the device and on the signet machine.
#[test]
fn an_expiry_renders_as_a_span_in_the_ledger_vocabulary() {
    assert_eq!(
        Expiry::Live { left: 34 * DAY }.to_string(),
        "expires in 34d"
    );
    assert_eq!(
        Expiry::Expiring { left: 12 * DAY }.to_string(),
        "expires in 12d"
    );
    assert_eq!(
        Expiry::Expired { ago: 6 * DAY }.to_string(),
        "expired 6d ago"
    );
    assert!(
        Expiry::Unknown.to_string().contains("unknown"),
        "the unreadable case must read as unknown, never as a span"
    );
}

/// The end-to-end read over a REAL signed badge, not a hand-made `Option`: a badge minted for a 90-day
/// TTL reads back as live with about 90 days left. This is the wire that proves the accessor is actually
/// being consulted, so the whole module cannot pass on a stubbed expiry.
#[test]
fn a_real_signed_badge_reads_its_own_minted_expiry() {
    let signet = Secret::ephemeral();
    let device = Secret::ephemeral();
    let badge = signet
        .sign_device_badge(device.node_id(), DEVICE_BADGE_TTL)
        .expect("sign a device badge");
    let expiry = Expiry::read(&badge, SystemTime::now()).expect("read the badge's own expiry");
    let Expiry::Live { left } = expiry else {
        panic!("a freshly minted 90-day badge is live, got {expiry:?}");
    };
    assert!(
        left > DEVICE_BADGE_TTL - DAY && left <= DEVICE_BADGE_TTL,
        "the reading is the minted TTL, got {left:?}"
    );
}
