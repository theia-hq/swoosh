//! Stored badge expiry dates, remaining-time classifications and renewal guidance.
//!
//! [`Expiry::read`] reads the authority's advisory date for display and warnings. It does not
//! account for attenuation. Local refusal in `reaching::into_slot` instead classifies
//! [`nauthy::Cap::valid_until`] with `Expiry::at`, using the effective inclusive bound.
//! Neither reading authorizes a request; admission still requires the gate's checks.
//!
//! [`DEFAULT_DURATION`]: crate::root::DEFAULT_DURATION

use core::fmt;
use core::time::Duration;
use std::time::SystemTime;

use bifrost::NodeId;
use nauthy::Link;

use crate::grants;

/// How long before a stored badge dies this device starts saying so, on every surface that renders an
/// [`Expiry`].
///
/// 14 days against a 90-day [`DEFAULT_DURATION`]: the device's own last warning, so it speaks for the
/// final fortnight rather than for a third of the badge's life, and still leaves the operator time to
/// reach the machine that holds the root. A missed renewal costs the uniform `not admitted` at the far
/// gate, which is the least actionable error in the system; a warning costs one line on stderr.
///
/// [`DEFAULT_DURATION`]: crate::root::DEFAULT_DURATION
pub const DEVICE_WARN_WINDOW: Duration = Duration::from_secs(14 * 24 * 60 * 60);

/// An optional expiry date classified at one instant using [`DEVICE_WARN_WINDOW`].
///
/// [`read`](Self::read) supplies the advisory date for display and warnings. Local refusal uses
/// `Expiry::at` with the effective bound instead. A classification does not establish admission
/// or revocation status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expiry {
    /// No date was supplied. This does not establish that the badge never expires.
    Unknown,
    /// The supplied date is before the classification time.
    Expired {
        /// Time since the supplied date.
        ago: Duration,
    },
    /// The supplied date is within [`DEVICE_WARN_WINDOW`], including equality.
    Expiring {
        /// Time until the supplied date.
        left: Duration,
    },
    /// The supplied date is more than [`DEVICE_WARN_WINDOW`] away.
    Live {
        /// Time until the supplied date.
        left: Duration,
    },
}

impl Expiry {
    /// Classify the authority's advisory expiry date as of `now`.
    ///
    /// Propagates read errors rather than guessing. Use the effective bound, not this advisory
    /// reading, for local expiry refusal.
    pub fn read(badge: &Link, now: SystemTime) -> eyre::Result<Self> {
        Ok(Self::at(badge.cap().expiry()?, now))
    }

    /// Classify an optional date against `now`, retaining equality as unexpired.
    /// `None` produces [`Unknown`](Self::Unknown); this helper reads no token and authorizes nothing.
    pub(crate) fn at(expiry: Option<SystemTime>, now: SystemTime) -> Self {
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
/// or the unreadable case. The span is [`grants::humanize`]d, the same rendering `status` gives
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

/// The one remedy every badge-expiry surface names, for the device whose key is `node`: renew it where the
/// root is kept, and this machine picks it up. Written once, here, so the refusal and the warning cannot
/// teach two different fixes for one problem.
#[must_use]
pub fn remedy(node: NodeId) -> String {
    format!(
        "where your root is kept: swoosh invite <name> {node}. This machine picks it up the next time it \
         reaches one of your devices (or now: swoosh sync)."
    )
}

#[cfg(test)]
#[path = "badge_tests.rs"]
mod badge_tests;
