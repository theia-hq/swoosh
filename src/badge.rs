//! What a stored membership badge can say about its OWN remaining life, and the one remedy that renews
//! it.
//!
//! The badge `adopt` stores is signed by the signet and stands for [`DEVICE_BADGE_TTL`], after which the
//! far gate refuses it. That expiry is enforced by a datalog CHECK the gate evaluates over the whole
//! chain, which no holder can read out; nauthy mints an advisory `expires_at` AUTHORITY fact beside the
//! check so the device CAN. This module is the single place that fact becomes a decision, so the
//! dial-time refusal, the renewal warning, and the `swoosh status` line read one clock and name one
//! fix instead of drifting into three.
//!
//! **The reading is an UPPER BOUND, never a lower one.** [`nauthy::Cap::expiry`] reads origin-0 facts
//! only, so a narrowing an attenuation block added is invisible here and a badge can be shorter-lived
//! than this module believes, never longer. That asymmetry is the whole reason a LOCAL refusal is sound:
//! it can let through a dial the gate will refuse (which costs what it costs today), and it can never
//! turn away a dial the gate would have admitted. Nothing here admits anything. The CHECK remains the
//! sole enforcement, and no admission path may read a [`Expiry`].
//!
//! [`DEVICE_BADGE_TTL`]: crate::identity::DEVICE_BADGE_TTL

use core::fmt;
use core::time::Duration;
use std::time::SystemTime;

use bifrost::NodeId;
use nauthy::Link;

use crate::grants;

/// How long before a stored badge dies this device starts saying so, on every surface that renders an
/// [`Expiry`].
///
/// 14 days against a 90-day [`DEVICE_BADGE_TTL`]: the device's own last warning, so it speaks for the
/// final fortnight rather than for a third of the badge's life, and still leaves the operator time to
/// reach the machine that holds the root. A missed renewal costs the uniform `not admitted` at the far
/// gate, which is the least actionable error in the system; a warning costs one line on stderr.
///
/// [`DEVICE_BADGE_TTL`]: crate::identity::DEVICE_BADGE_TTL
pub const DEVICE_WARN_WINDOW: Duration = Duration::from_secs(14 * 24 * 60 * 60);

/// What a membership badge's own `expires_at` fact says about its remaining life at one instant.
///
/// An enum and not a bare `Option<Duration>` because four different things happen at a decision site and
/// each must be spelled: a dial REFUSES on [`Expired`](Self::Expired), WARNS on
/// [`Expiring`](Self::Expiring), and says nothing on [`Live`](Self::Live) or [`Unknown`](Self::Unknown).
/// The window is applied once, here, at construction, so no caller re-derives "is it close" from a
/// duration and no two callers can pick different windows.
///
/// This answers EXPIRY, never validity. A badge revoked through the denylist reads `Live` here,
/// because revocation is checked at the gate and the holder's own machine has no copy of the
/// list. So a surface built on this states how long a badge has LEFT, and must not claim the
/// badge still works.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expiry {
    /// The badge carries no `expires_at` fact, so this device cannot say when it dies. A badge minted
    /// before the fact existed, whose expiry lives only in the unreadable check. NOT "it never expires":
    /// every surface renders it as unknown, and every guard falls back to what it did before the fact.
    Unknown,
    /// The badge died `ago` ago. The gate will refuse it, so a dial that would present it is refused
    /// here instead, where the cause can be named.
    Expired {
        /// How long ago the expiry passed.
        ago: Duration,
    },
    /// The badge still stands, with `left` to run, and `left` is inside [`DEVICE_WARN_WINDOW`]: the operator
    /// is told, and the dial goes ahead.
    Expiring {
        /// How long the badge has left.
        left: Duration,
    },
    /// The badge still stands with more than [`DEVICE_WARN_WINDOW`] to run. Nothing is said.
    Live {
        /// How long the badge has left.
        left: Duration,
    },
}

impl Expiry {
    /// Read `badge`'s remaining life as of `now`.
    ///
    /// Fails only when the datalog read itself fails, which is not "unexpired" and not "expired": the
    /// caller propagates it rather than guessing, so a dial that cannot answer the question fails with
    /// the real cause instead of proceeding on an assumption.
    pub fn read(badge: &Link, now: SystemTime) -> eyre::Result<Self> {
        Ok(Self::at(badge.cap().expiry()?, now))
    }

    /// Classify a raw expiry reading against `now`. Split from [`read`](Self::read) so the whole
    /// decision, including the unreadable case, is a pure function a test can drive at every boundary:
    /// the `expires_at`-less badge that produces `None` can only be minted inside nauthy.
    fn at(expiry: Option<SystemTime>, now: SystemTime) -> Self {
        let Some(expiry) = expiry else {
            return Self::Unknown;
        };
        match expiry.duration_since(now) {
            Ok(left) if left <= DEVICE_WARN_WINDOW => Self::Expiring { left },
            Ok(left) => Self::Live { left },
            // `duration_since` reports the gap the other way round when the instant is in the past, so
            // the error's payload is exactly how long the badge has been dead.
            Err(past) => Self::Expired {
                ago: past.duration(),
            },
        }
    }
}

/// The fragment every expiry surface prints about the badge itself: `expires in 34d`, `expired 6d ago`,
/// or the unreadable case. The span is [`grants::humanize`]d, the same rendering `invite ls` gives
/// the issuer side, so one badge reads the same on both machines.
impl fmt::Display for Expiry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown => write!(formatter, "expiry unknown (this badge does not carry one)"),
            Self::Expired { ago } => write!(formatter, "expired {} ago", grants::humanize(*ago)),
            Self::Expiring { left } | Self::Live { left } => {
                write!(formatter, "expires in {}", grants::humanize(*left))
            }
        }
    }
}

/// The one remedy every badge-expiry surface names, for the device whose key is `node`.
///
/// Renewal is re-enrolment: the signet holder re-runs `invite add` for this key and this machine adopts
/// the result, which is why there is no renew verb. Written once, here, so the refusal and the warning
/// cannot teach two different fixes for one problem, and so the day the enrolment door changes there is
/// one line to change.
#[must_use]
pub fn remedy(node: NodeId) -> String {
    format!(
        "ask the signet holder for a fresh invite (`swoosh invite add <label> --for {node}`) and adopt \
         it here with `swoosh adopt`"
    )
}

#[cfg(test)]
#[path = "badge_tests.rs"]
mod badge_tests;
