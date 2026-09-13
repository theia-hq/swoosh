//! The responder-side bounds a diagnostic route enforces, one construction choice.
//!
//! A diagnostic handler is built METERED ([`Limits::metered`]: a one-second probe interval per verified
//! caller, one transfer slot, a 64 MiB per-direction byte cap, a 15-second stream cap) or UNMETERED
//! ([`Limits::unmetered`]: mirror the client until it stops). The composing consumer makes the choice per
//! route at construction and reports it through the handler's metering, so a banner warns exactly when an
//! OPEN service is unbounded. A configuration that bounds nothing reads unmetered, the fail-loud
//! direction: a forgotten override produces a warning, never silence.

use core::time::Duration;

use crate::responder::SpeedCaps;

/// The minimum spacing between two probes from one caller under metered limits.
const PING_MIN_INTERVAL: Duration = Duration::from_secs(1);
/// The largest payload a metered speed run moves per direction.
const SPEED_MAX_BYTES: u64 = 64 * 1024 * 1024;
/// The longest a metered speed stream may run.
const SPEED_MAX_DURATION: Duration = Duration::from_secs(15);

/// The responder-side bounds a diagnostic service enforces, configured once by the assembly and read by
/// the `ping` and `speed` handlers.
///
/// Two constructors: [`metered`](Self::metered) installs this node's default bounds (a one-second probe
/// interval, one transfer slot, a 64 MiB per-direction cap, a 15-second stream cap), and
/// [`unmetered`](Self::unmetered) installs none, which preserves the old mirror-the-client behavior and
/// carries the `Unmetered` banner caveat. The two are the operator's deliberate choice, never a default
/// that flips silently.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    ping_interval: Option<Duration>,
    speed_slots: Option<usize>,
    speed_max_bytes: Option<u64>,
    speed_max_duration: Option<Duration>,
}

impl Limits {
    /// This node's default bounds: a metered responder.
    pub fn metered() -> Self {
        Self {
            ping_interval: Some(PING_MIN_INTERVAL),
            speed_slots: Some(1),
            speed_max_bytes: Some(SPEED_MAX_BYTES),
            speed_max_duration: Some(SPEED_MAX_DURATION),
        }
    }

    /// No responder-side bounds: every run mirrors the client until it stops.
    pub fn unmetered() -> Self {
        Self {
            ping_interval: None,
            speed_slots: None,
            speed_max_bytes: None,
            speed_max_duration: None,
        }
    }

    /// Whether this configuration bounds what a caller may consume. False when nothing is bounded, which
    /// is the fail-loud direction: an open route that reports unmetered gets the banner caveat.
    pub fn is_metered(&self) -> bool {
        self.ping_interval.is_some()
            || self.speed_slots.is_some()
            || self.speed_max_bytes.is_some()
            || self.speed_max_duration.is_some()
    }

    /// The minimum spacing between one caller's probes, or `None` when the probe bound is off.
    pub fn ping_interval(&self) -> Option<Duration> {
        self.ping_interval
    }

    /// How many transfers may run at once, or `None` when the concurrency bound is off.
    pub fn speed_slots(&self) -> Option<usize> {
        self.speed_slots
    }

    /// The caps a speed stream runs under. Crate-private: the responder derives them from the same
    /// configuration the handler passes through whole.
    pub(crate) fn speed_caps(&self) -> SpeedCaps {
        SpeedCaps {
            max_bytes: self.speed_max_bytes,
            max_duration: self.speed_max_duration,
        }
    }
}

#[cfg(test)]
mod limits_tests {
    use super::{Limits, PING_MIN_INTERVAL, SPEED_MAX_BYTES, SPEED_MAX_DURATION};

    /// The metering a banner narrates is derived from the configured bounds, never a frozen flag.
    #[test]
    fn metering_reads_the_limits() {
        assert!(Limits::metered().is_metered());
        assert!(!Limits::unmetered().is_metered());
    }

    /// The ping bound is the metered default; the unmetered configuration spaces nothing.
    #[test]
    fn the_ping_interval_is_the_metered_default() {
        assert_eq!(Limits::metered().ping_interval(), Some(PING_MIN_INTERVAL));
        assert_eq!(Limits::unmetered().ping_interval(), None);
    }

    /// The byte cap clamps an explicit request and bounds an unbounded one, so a metered run terminates
    /// on the responder's own byte count.
    #[test]
    fn the_caps_clamp_a_request_and_bound_an_unbounded_one() {
        let caps = Limits::metered().speed_caps();
        assert_eq!(caps.clamp(Some(u64::MAX)), Some(SPEED_MAX_BYTES));
        assert_eq!(caps.clamp(Some(1)), Some(1));
        assert_eq!(caps.clamp(None), Some(SPEED_MAX_BYTES));
        let unbounded = Limits::unmetered().speed_caps();
        assert_eq!(unbounded.clamp(None), None);
        assert_eq!(unbounded.clamp(Some(7)), Some(7));
    }

    /// The stream cap rides the limits with the byte cap: metered carries the wall clock, unmetered leaves
    /// the stream open so a run still mirrors the client.
    #[test]
    fn the_stream_cap_rides_the_limits() {
        assert_eq!(
            Limits::metered().speed_caps().max_duration,
            Some(SPEED_MAX_DURATION)
        );
        assert_eq!(Limits::unmetered().speed_caps().max_duration, None);
    }
}
